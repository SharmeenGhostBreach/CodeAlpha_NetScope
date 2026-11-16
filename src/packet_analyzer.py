
from collections import Counter
from datetime import datetime
import os
import signal

from scapy.all import (
    sniff,
    wrpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6MLReport2,
)

# ---------------------------------
# Configuration
# ---------------------------------

INTERFACE = "eth0"
PACKET_LIMIT = 20

# None captures all traffic.
# Examples: "tcp", "udp", "icmp", "port 53"
CAPTURE_FILTER = None

protocol_counts = Counter()
class CaptureInterrupted(Exception):
    """Raised when the user manually stops packet capture."""


def handle_interrupt(signum, frame):
    """Handle Ctrl+C without Scapy swallowing the interruption."""
    raise CaptureInterrupted

def get_timestamp(packet):
    """Return the packet capture timestamp."""

    if hasattr(packet, "time"):
        return datetime.fromtimestamp(
            float(packet.time)
        ).strftime("%Y-%m-%d %H:%M:%S")

    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def analyze_packet(packet):
    """Extract and display useful packet information."""

    timestamp = get_timestamp(packet)

    source_ip = "Unknown"
    destination_ip = "Unknown"
    protocol = "Other"

    source_port = "-"
    destination_port = "-"

    payload_size = 0
    details = "-"

    # 1. Identify network-layer addresses

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    # 2. Identify ARP packets

    if ARP in packet:
        protocol = "ARP"

        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst

        details = (
            "ARP operation: "
            + str(packet[ARP].op)
        )

    # 3. Identify TCP packets

    elif TCP in packet:
        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        payload_size = len(
            bytes(packet[TCP].payload)
        )

    # 4. Identify UDP packets

    elif UDP in packet:
        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

        payload_size = len(
            bytes(packet[UDP].payload)
        )

    # 5. Identify IPv4 ICMP

    elif ICMP in packet:
        protocol = "ICMP"

        details = (
            "ICMP type: "
            + str(packet[ICMP].type)
            + ", code: "
            + str(packet[ICMP].code)
        )

        payload_size = len(
            bytes(packet[ICMP].payload)
        )

    # 6. Identify IPv6 ICMP and subtypes

    elif IPv6 in packet:
        icmpv6_types = [
            (ICMPv6EchoRequest, "ICMPv6 Echo Request"),
            (ICMPv6EchoReply, "ICMPv6 Echo Reply"),
            (ICMPv6ND_NS, "ICMPv6 Neighbor Solicitation"),
            (ICMPv6ND_NA, "ICMPv6 Neighbor Advertisement"),
            (ICMPv6ND_RA, "ICMPv6 Router Advertisement"),
            (ICMPv6ND_RS, "ICMPv6 Router Solicitation"),
            (ICMPv6MLReport2, "ICMPv6 Multicast Listener Report"),
        ]

        for layer, label in icmpv6_types:
            if layer in packet:
                protocol = "ICMPv6"
                details = label
                break

        # Generic ICMPv6 detection
        if protocol == "Other" and packet.haslayer(58):
            protocol = "ICMPv6"
            details = "Other ICMPv6 message"

    # 7. Identify DNS queries and responses

    if DNS in packet:
        protocol = "DNS"

        dns_layer = packet[DNS]

        if dns_layer.qr == 0:
            message_type = "Query"
        else:
            message_type = "Response"

        if DNSQR in packet:
            query_name = packet[DNSQR].qname

            if isinstance(query_name, bytes):
                query_name = query_name.decode(
                    errors="replace"
                )

            details = (
                f"DNS {message_type}: "
                f"{str(query_name).rstrip('.')}"
            )
        else:
            details = f"DNS {message_type}"

        if dns_layer.qr == 1:
            details += (
                f" (answers: {dns_layer.ancount})"
            )

    # 8. Update protocol statistics

    protocol_counts[protocol] += 1

    # 9. Display packet information

    print("\n" + "=" * 65)
    print("NETWORK PACKET DETECTED")
    print("=" * 65)

    print("Timestamp       :", timestamp)
    print("Source IP       :", source_ip)
    print("Destination IP  :", destination_ip)
    print("Protocol        :", protocol)
    print("Source Port     :", source_port)
    print("Destination Port:", destination_port)
    print("Packet Size     :", len(packet), "bytes")
    print("Payload Size    :", payload_size, "bytes")
    print("Details         :", details)


def handle_packet(packet, captured_packets):
    """Store each packet and analyze it."""

    captured_packets.append(packet)
    analyze_packet(packet)


def print_statistics():
    """Display protocol capture statistics."""

    print("\n" + "=" * 45)
    print("        PROTOCOL STATISTICS")
    print("=" * 45)

    for name, total in sorted(protocol_counts.items()):
        print(f"{name:<15}: {total}")

    print("-" * 45)
    print(
        f"{'Total Packets':<15}: "
        f"{sum(protocol_counts.values())}"
    )


def save_capture(captured_packets):
    """Save captured packets to a PCAP file."""

    if not captured_packets:
        print("\nNo packets captured. PCAP file not created.")
        return

    output_file = "logs/network_capture.pcap"

    try:
        os.makedirs("logs", exist_ok=True)

        wrpcap(output_file, captured_packets)

        print("\nPCAP file saved successfully!")
        print("File:", output_file)
        print("Packets saved:", len(captured_packets))

    except OSError as error:
        print("\nCould not save PCAP file:", error)



def main():

    captured_packets = []

    print("=" * 65)
    print("             NETSCOPE")
    print("=" * 65)

    print("Interface:", INTERFACE)
    print("Packet Limit:", PACKET_LIMIT)
    print("Capture Filter:", CAPTURE_FILTER)

    print("\nWaiting for network packets...\n")

    previous_handler = signal.signal(
        signal.SIGINT, handle_interrupt
    )

    try:
        sniff(
            iface=INTERFACE,
            filter=CAPTURE_FILTER,
            prn=lambda packet: handle_packet(
                packet, captured_packets
            ),
            count=PACKET_LIMIT,
            store=False
        )

        print("\nCapture limit reached or capture completed.")

    except CaptureInterrupted:
        print("\nCapture stopped by user.")

    except PermissionError:
        print(
            "\nError: Packet capture requires "
            "elevated privileges."
        )

    except OSError as error:
        print("\nNetwork capture error:", error)

    finally:
        signal.signal(signal.SIGINT, previous_handler)

        # Save packets even if capture was interrupted.
        save_capture(captured_packets)

        print_statistics()

        print("\nPacket capture session completed.")



if __name__ == "__main__":
    main()
