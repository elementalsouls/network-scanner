"""Tests for network utility functions."""
import pytest
from scanner.core.network_utils import (
    parse_targets,
    is_valid_ip,
    ip_to_int,
    int_to_ip,
    calculate_subnet_info,
    resolve_hostname,
)


class TestIsValidIp:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("255.255.255.255") is True
        assert is_valid_ip("0.0.0.0") is True

    def test_invalid_ipv4(self):
        assert is_valid_ip("256.1.1.1") is False
        assert is_valid_ip("not-an-ip") is False
        assert is_valid_ip("") is False
        assert is_valid_ip("192.168.1") is False
        assert is_valid_ip("192.168.1.1.1") is False


class TestIpConversion:
    def test_ip_to_int(self):
        assert ip_to_int("0.0.0.0") == 0
        assert ip_to_int("0.0.0.1") == 1
        assert ip_to_int("255.255.255.255") == 4294967295
        assert ip_to_int("192.168.1.1") == 3232235777

    def test_int_to_ip(self):
        assert int_to_ip(0) == "0.0.0.0"
        assert int_to_ip(1) == "0.0.0.1"
        assert int_to_ip(4294967295) == "255.255.255.255"
        assert int_to_ip(3232235777) == "192.168.1.1"

    def test_roundtrip(self):
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.100.200"]:
            assert int_to_ip(ip_to_int(ip)) == ip


class TestParseTargets:
    def test_single_ip(self):
        result = parse_targets("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_cidr_slash24(self):
        result = parse_targets("192.168.1.0/24")
        assert len(result) == 254
        assert "192.168.1.1" in result
        assert "192.168.1.254" in result
        assert "192.168.1.0" not in result  # network address

    def test_cidr_slash30(self):
        result = parse_targets("10.0.0.0/30")
        assert len(result) == 2
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result

    def test_ip_range_short(self):
        result = parse_targets("192.168.1.1-5")
        assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"]

    def test_ip_range_full(self):
        result = parse_targets("10.0.0.1-10.0.0.3")
        assert result == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_invalid_target(self):
        result = parse_targets("not.a.valid.target.xyz.invalid")
        assert result == []

    def test_single_ip_slash32(self):
        result = parse_targets("10.0.0.1/32")
        # /32 has 1 host
        assert "10.0.0.1" in result


class TestCalculateSubnetInfo:
    def test_slash24(self):
        info = calculate_subnet_info("192.168.1.0/24")
        assert info["network"] == "192.168.1.0"
        assert info["broadcast"] == "192.168.1.255"
        assert info["netmask"] == "255.255.255.0"
        assert info["prefix_length"] == 24
        assert info["num_hosts"] == 254
        assert info["first_host"] == "192.168.1.1"
        assert info["last_host"] == "192.168.1.254"

    def test_slash30(self):
        info = calculate_subnet_info("10.0.0.0/30")
        assert info["num_hosts"] == 2
        assert info["prefix_length"] == 30

    def test_slash16(self):
        info = calculate_subnet_info("172.16.0.0/16")
        assert info["num_hosts"] == 65534
        assert info["prefix_length"] == 16

    def test_invalid_cidr(self):
        with pytest.raises(ValueError):
            calculate_subnet_info("not-a-cidr")
