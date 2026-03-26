"""Tests for MAC vendor lookup."""
import pytest
from scanner.core.mac_vendor import MacVendorLookup, _normalize_mac, _get_oui, get_mac_from_arp


class TestNormalizeMac:
    def test_colon_format(self):
        assert _normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_dash_format(self):
        assert _normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_no_separator(self):
        assert _normalize_mac("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:FF"

    def test_already_normalized(self):
        assert _normalize_mac("00:1A:11:AA:BB:CC") == "00:1A:11:AA:BB:CC"


class TestGetOui:
    def test_extracts_first_three_octets(self):
        assert _get_oui("00:1A:11:AA:BB:CC") == "00:1A:11"

    def test_lowercase_input(self):
        oui = _get_oui("b8:27:eb:aa:bb:cc")
        assert oui == "B8:27:EB"


class TestMacVendorLookup:
    @pytest.fixture
    def lookup(self):
        return MacVendorLookup(use_api=False)

    def test_known_vendor_vmware(self, lookup):
        vendor = lookup.lookup("00:50:56:aa:bb:cc")
        assert vendor == "VMware"

    def test_known_vendor_cisco(self, lookup):
        vendor = lookup.lookup("00:00:0C:aa:bb:cc")
        assert vendor == "Cisco Systems"

    def test_known_vendor_raspberry_pi(self, lookup):
        vendor = lookup.lookup("B8:27:EB:00:11:22")
        assert vendor == "Raspberry Pi Foundation"

    def test_known_vendor_apple(self, lookup):
        vendor = lookup.lookup("00:1B:63:aa:bb:cc")
        assert vendor == "Apple"

    def test_unknown_vendor_returns_none(self, lookup):
        vendor = lookup.lookup("FF:FF:FF:FF:FF:FF")
        assert vendor is None

    def test_empty_mac_returns_none(self, lookup):
        vendor = lookup.lookup("")
        assert vendor is None

    def test_caching(self, lookup):
        # First lookup
        vendor1 = lookup.lookup("00:50:56:00:00:01")
        # Second lookup (from cache)
        vendor2 = lookup.lookup("00:50:56:00:00:02")
        assert vendor1 == vendor2 == "VMware"

    def test_get_all_vendors(self, lookup):
        vendors = lookup.get_all_vendors()
        assert isinstance(vendors, dict)
        assert len(vendors) >= 50
        assert "00:50:56" in vendors

    def test_dash_format_lookup(self, lookup):
        vendor = lookup.lookup("00-50-56-aa-bb-cc")
        assert vendor == "VMware"

    def test_intel_lookup(self, lookup):
        vendor = lookup.lookup("00:02:B3:11:22:33")
        assert vendor == "Intel"
