# NetScope — Usage Guide

## 1. Overview

NetScope is a Python-based network traffic analyzer built with Scapy.
It captures live network packets, identifies supported protocols,
displays packet metadata and exports captured packets to PCAP format.

## 2. Requirements

- Linux system
- Python 3
- Scapy 2.8.0
- Network interface available for packet capture
- Elevated privileges for live packet capture

## 3. Installation

Clone the repository:

    git clone YOUR_REPOSITORY_URL
    cd YOUR_REPOSITORY_FOLDER

Create and activate a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## 4. Configuration

Open the analyzer:

    nano src/packet_analyzer.py

Review these configuration values near the top:

    INTERFACE = "eth0"
    PACKET_LIMIT = 20
    CAPTURE_FILTER = None

Set INTERFACE to the network interface you intend to monitor.

List available interfaces with:

    ip link show

PACKET_LIMIT controls how many packets are captured.
Use 0 for continuous capture until manually interrupted.

CAPTURE_FILTER accepts a Berkeley Packet Filter expression.
Use None to capture all traffic.

Examples:

    CAPTURE_FILTER = "tcp"
    CAPTURE_FILTER = "udp"
    CAPTURE_FILTER = "icmp"
    CAPTURE_FILTER = "udp port 53"

Save the file after making configuration changes.

## 5. Run NetScope

From the project root, run:

    sudo .venv/bin/python src/packet_analyzer.py

NetScope displays packet timestamps, source and destination
addresses, protocols, ports, packet sizes, payload sizes and details.

Press Ctrl+C to stop a continuous capture safely.

## 6. PCAP Export

Captured packets are saved to:

    logs/network_capture.pcap

Open the PCAP file using Wireshark:

    wireshark logs/network_capture.pcap

The logs directory is excluded from Git because packet captures
may contain sensitive network information.

## 7. Supported Protocol Analysis

NetScope currently identifies and analyzes:

- IPv4 and IPv6 addresses
- TCP and UDP
- IPv4 ICMP
- Selected ICMPv6 messages
- ARP
- DNS queries and responses

## 8. Automated Tests

Run the automated tests without starting a live capture:

    python -m unittest discover -s tests -v

See TESTING.md for test coverage and details.

## 9. Responsible Use

Only capture traffic on networks and devices you own or have
explicit permission to monitor.

Packet captures may contain sensitive metadata and should be
handled securely.

NetScope displays packet metadata and does not decrypt HTTPS
or other encrypted application traffic.
