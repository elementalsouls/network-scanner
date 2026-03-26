"""XML output formatter."""
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime

from scanner.models.scan_result import ScanResult


class XMLOutput:
    """Output scan results as XML."""

    def format(self, result: ScanResult) -> str:
        """Format a ScanResult as an XML string."""
        root = ET.Element("scan_result")
        root.set("scan_id", result.scan_id)
        root.set("target", result.target)
        if result.profile:
            root.set("profile", result.profile)
        if result.start_time:
            root.set("start_time", result.start_time.isoformat())
        if result.end_time:
            root.set("end_time", result.end_time.isoformat())
        if result.duration is not None:
            root.set("duration", f"{result.duration:.2f}")

        stats_el = ET.SubElement(root, "stats")
        stats_el.set("hosts_found", str(len(result.hosts)))
        stats_el.set("alive_hosts", str(len(result.alive_hosts)))
        stats_el.set("ports_scanned", str(result.ports_scanned))
        stats_el.set("total_open_ports", str(result.total_open_ports))

        hosts_el = ET.SubElement(root, "hosts")
        for host in result.hosts:
            host_el = ET.SubElement(hosts_el, "host")
            host_el.set("ip", host.ip)
            host_el.set("is_alive", str(host.is_alive).lower())
            if host.hostname:
                host_el.set("hostname", host.hostname)
            if host.mac:
                host_el.set("mac", host.mac)
            if host.vendor:
                host_el.set("vendor", host.vendor)
            if host.os:
                host_el.set("os", host.os)
            if host.ttl is not None:
                host_el.set("ttl", str(host.ttl))
            if host.response_time is not None:
                host_el.set("response_time", f"{host.response_time:.2f}")

            if host.ports:
                ports_el = ET.SubElement(host_el, "ports")
                for port in host.ports:
                    port_el = ET.SubElement(ports_el, "port")
                    port_el.set("number", str(port.number))
                    port_el.set("protocol", port.protocol.value)
                    port_el.set("state", port.state.value)
                    if port.service:
                        port_el.set("service", port.service)
                    if port.version:
                        port_el.set("version", port.version)
                    if port.banner:
                        banner_el = ET.SubElement(port_el, "banner")
                        banner_el.text = port.banner[:256]

        xml_str = ET.tostring(root, encoding="unicode")
        return minidom.parseString(xml_str).toprettyxml(indent="  ")

    def write(self, result: ScanResult, filepath: str) -> None:
        """Write XML output to a file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.format(result))
