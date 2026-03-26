"""Tests for output formatters."""
import json
import csv
import io
import pytest
from xml.etree import ElementTree as ET

from scanner.output.json_output import JSONOutput
from scanner.output.csv_output import CSVOutput
from scanner.output.xml_output import XMLOutput
from scanner.output.html_report import HTMLReport
from scanner.output.console_output import print_full_results, print_scan_summary


class TestJSONOutput:
    def test_format_returns_valid_json(self, sample_scan_result):
        output = JSONOutput()
        result_str = output.format(sample_scan_result)
        data = json.loads(result_str)
        assert data["target"] == "192.168.1.0/24"
        assert "hosts" in data

    def test_format_includes_hosts(self, sample_scan_result):
        output = JSONOutput()
        result_str = output.format(sample_scan_result)
        data = json.loads(result_str)
        assert len(data["hosts"]) == 2

    def test_format_includes_stats(self, sample_scan_result):
        output = JSONOutput()
        data = json.loads(output.format(sample_scan_result))
        assert data["alive_hosts"] == 1
        assert data["total_open_ports"] == 2

    def test_parse_roundtrip(self, sample_scan_result):
        output = JSONOutput()
        json_str = output.format(sample_scan_result)
        result2 = output.parse(json_str)
        assert result2.target == sample_scan_result.target
        assert result2.scan_id == sample_scan_result.scan_id

    def test_write_to_file(self, sample_scan_result, tmp_path):
        filepath = str(tmp_path / "output.json")
        JSONOutput().write(sample_scan_result, filepath)
        with open(filepath) as f:
            data = json.load(f)
        assert data["target"] == sample_scan_result.target


class TestCSVOutput:
    def test_format_ports_header(self, sample_scan_result):
        output = CSVOutput()
        csv_str = output.format_ports(sample_scan_result)
        reader = csv.DictReader(io.StringIO(csv_str))
        assert "ip" in reader.fieldnames
        assert "port" in reader.fieldnames

    def test_format_ports_rows(self, sample_scan_result):
        output = CSVOutput()
        csv_str = output.format_ports(sample_scan_result)
        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)
        # 2 open ports on the alive host
        assert len(rows) == 2

    def test_format_hosts(self, sample_scan_result):
        output = CSVOutput()
        csv_str = output.format_hosts(sample_scan_result)
        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)
        assert len(rows) == 2  # both hosts (alive + down)

    def test_write_to_file(self, sample_scan_result, tmp_path):
        filepath = str(tmp_path / "output.csv")
        CSVOutput().write(sample_scan_result, filepath)
        with open(filepath) as f:
            content = f.read()
        assert "ip" in content
        assert "192.168.1.1" in content


class TestXMLOutput:
    def test_format_valid_xml(self, sample_scan_result):
        output = XMLOutput()
        xml_str = output.format(sample_scan_result)
        root = ET.fromstring(xml_str.split("\n", 1)[1])  # skip xml declaration line
        assert root.tag == "scan_result"

    def test_format_includes_stats(self, sample_scan_result):
        output = XMLOutput()
        xml_str = output.format(sample_scan_result)
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        stats = root.find("stats")
        assert stats is not None
        assert stats.get("alive_hosts") == "1"

    def test_format_includes_hosts(self, sample_scan_result):
        output = XMLOutput()
        xml_str = output.format(sample_scan_result)
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        hosts = root.findall(".//host")
        assert len(hosts) == 2

    def test_write_to_file(self, sample_scan_result, tmp_path):
        filepath = str(tmp_path / "output.xml")
        XMLOutput().write(sample_scan_result, filepath)
        tree = ET.parse(filepath)
        assert tree.getroot().tag == "scan_result"


class TestHTMLReport:
    def test_format_returns_html(self, sample_scan_result):
        report = HTMLReport()
        html = report.format(sample_scan_result)
        assert "<!DOCTYPE html>" in html
        assert "192.168.1.0/24" in html

    def test_format_includes_stats(self, sample_scan_result):
        report = HTMLReport()
        html = report.format(sample_scan_result)
        assert "Alive Hosts" in html
        assert "Open Ports" in html

    def test_format_includes_host_ip(self, sample_scan_result):
        report = HTMLReport()
        html = report.format(sample_scan_result)
        assert "192.168.1.1" in html

    def test_write_to_file(self, sample_scan_result, tmp_path):
        filepath = str(tmp_path / "report.html")
        HTMLReport().write(sample_scan_result, filepath)
        with open(filepath) as f:
            content = f.read()
        assert "Network Scan Report" in content


class TestConsoleOutput:
    def test_print_full_results_no_error(self, sample_scan_result):
        from rich.console import Console
        console = Console(file=io.StringIO())
        print_full_results(sample_scan_result, console=console)

    def test_print_scan_summary_no_error(self, sample_scan_result):
        from rich.console import Console
        console = Console(file=io.StringIO())
        print_scan_summary(sample_scan_result, console=console)
