# NetScope — Network Traffic Analyzer

NetScope is a Python-based network traffic analysis tool built with
**Scapy**. It captures live network packets, identifies supported
protocols, displays packet metadata, tracks protocol statistics,
and exports captured traffic in PCAP format for further inspection.

## Features

- Live packet capture on a selected network interface.
- IPv4 and IPv6 source and destination address identification.
- TCP, UDP, ICMP, ICMPv6, ARP and DNS identification.
- TCP and UDP source and destination port analysis.
- DNS query and response identification.
- Selected ICMPv6 message identification.
- Packet and payload size reporting.
- Configurable Berkeley Packet Filter (BPF) filters.
- Protocol statistics after capture.
- PCAP export for offline Wireshark inspection.
- Graceful Ctrl+C interruption with captured packets saved before exit.

## Technology Stack

- Python 3
- Scapy 2.8.0
- Wireshark (optional)
- Kali Linux / Linux

## Project Structure

```text
NetScope-Network-Traffic-Analyzer/
├── src/
│   └── packet_analyzer.py
├── tests/
│   └── test_packet_analyzer.py
├── docs/
│   ├── TESTING.md
│   └── USAGE.md
├── capture_test.py
├── first_packet.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/SharmeenGhostBreach/NetScope-Network-Traffic-Analyzer.git
cd NetScope-Network-Traffic-Analyzer
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Open `src/packet_analyzer.py` and adjust these settings:

```python
INTERFACE = "eth0"
PACKET_LIMIT = 20
CAPTURE_FILTER = None
```

- `INTERFACE`: Network interface to monitor.
- `PACKET_LIMIT`: Maximum packets to capture. Use `0` for continuous capture.
- `CAPTURE_FILTER`: Optional BPF filter, such as `"tcp"` or `"udp port 53"`.

Check available interfaces:

```bash
ip link show
```

## Usage

Run the analyzer with elevated privileges:

```bash
sudo .venv/bin/python src/packet_analyzer.py
```

Press `Ctrl+C` to stop continuous capture gracefully.

Captured packets are saved to:

```text
logs/network_capture.pcap
```

Open the PCAP file in Wireshark for deeper inspection.

## Automated Tests

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

The project includes seven automated tests covering IPv4 TCP, UDP, ARP, DNS, IPv6, packet handling, and protocol statistics.

See [docs/TESTING.md](docs/TESTING.md) for details.

## Documentation

- [Usage Guide](docs/USAGE.md)
- [Testing Guide](docs/TESTING.md)

## Limitations

- HTTPS application data is not decrypted.
- Analysis is limited to supported protocols and packet fields.
- Packet capture may require root or appropriate network capabilities.
- Interface names and available protocols depend on the host system.

## Responsible Use

Use NetScope only on networks and systems you own or have explicit permission to monitor. Captured traffic may contain sensitive information; handle PCAP files responsibly.

## About

NetScope is an independent hands-on network analysis project built with Python and Scapy to explore packet capture, protocol analysis, and network troubleshooting.
