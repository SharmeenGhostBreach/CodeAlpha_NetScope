import unittest
from contextlib import redirect_stdout
from io import StringIO

from scapy.all import (
    IP,
    IPv6,
    TCP,
    UDP,
    ARP,
    DNS,
    DNSQR,
    Raw,
    ICMPv6EchoRequest,
)

from src import packet_analyzer


class TestNetScopeAnalyzer(unittest.TestCase):

    def setUp(self):
        packet_analyzer.protocol_counts.clear()

    def analyze_and_capture(self, packet):
        output = StringIO()

        with redirect_stdout(output):
            packet_analyzer.analyze_packet(packet)

        return output.getvalue()

    def test_ipv4_tcp_packet(self):
        packet = (
            IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=12345, dport=443)
            / Raw(load=b"hello")
        )

        output = self.analyze_and_capture(packet)

        self.assertIn("Protocol        : TCP", output)
        self.assertIn("192.168.1.10", output)
        self.assertIn("192.168.1.20", output)
        self.assertIn("Source Port     : 12345", output)
        self.assertIn("Destination Port: 443", output)
        self.assertIn("Payload Size    : 5 bytes", output)

    def test_udp_packet(self):
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=5000, dport=5001)
            / Raw(load=b"test")
        )

        output = self.analyze_and_capture(packet)

        self.assertIn("Protocol        : UDP", output)
        self.assertIn("Source Port     : 5000", output)
        self.assertIn("Destination Port: 5001", output)

    def test_arp_packet(self):
        packet = ARP(
            op=1,
            psrc="192.168.1.10",
            pdst="192.168.1.1"
        )

        output = self.analyze_and_capture(packet)

        self.assertIn("Protocol        : ARP", output)
        self.assertIn("192.168.1.10", output)
        self.assertIn("192.168.1.1", output)

    def test_dns_query(self):
        packet = (
            IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname="example.com")
            )
        )

        output = self.analyze_and_capture(packet)

        self.assertIn("Protocol        : DNS", output)
        self.assertIn("DNS Query: example.com", output)

    def test_ipv6_packet(self):
        packet = (
            IPv6(
                src="2001:db8::1",
                dst="2001:db8::2"
            )
            / ICMPv6EchoRequest()
        )

        output = self.analyze_and_capture(packet)

        self.assertIn("Protocol        : ICMPv6", output)
        self.assertIn("ICMPv6 Echo Request", output)
        self.assertIn("2001:db8::1", output)

    def test_handle_packet_stores_packet(self):
        packet = IP() / TCP()
        captured_packets = []

        output = StringIO()

        with redirect_stdout(output):
            packet_analyzer.handle_packet(
                packet,
                captured_packets
            )

        self.assertEqual(len(captured_packets), 1)
        self.assertIs(captured_packets[0], packet)
        self.assertEqual(packet_analyzer.protocol_counts["TCP"], 1)

    def test_protocol_statistics(self):
        packet_analyzer.protocol_counts.update({
            "TCP": 2,
            "UDP": 1,
            "DNS": 1
        })

        output = StringIO()

        with redirect_stdout(output):
            packet_analyzer.print_statistics()

        result = output.getvalue()

        self.assertIn("TCP", result)
        self.assertIn("UDP", result)
        self.assertIn("DNS", result)
        self.assertIn("Total Packets", result)
        self.assertIn("4", result)


if __name__ == "__main__":
    unittest.main()
