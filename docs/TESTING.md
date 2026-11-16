# NetScope — Testing Guide

## Test Framework

NetScope uses Python's built-in unittest framework and Scapy to
create synthetic network packets for repeatable testing.

## Running the Tests

Activate the project virtual environment:

    source .venv/bin/activate

Run the complete test suite:

    python -m unittest discover -s tests -v

## Current Test Coverage

| Test | Expected behavior |
|---|---|
| IPv4 TCP | Identifies TCP, addresses, ports and payload size |
| UDP | Identifies UDP and source/destination ports |
| ARP | Identifies ARP and sender/target IP addresses |
| DNS query | Identifies DNS queries and domain names |
| IPv6 | Identifies ICMPv6 Echo Request |
| Packet handling | Stores packets and updates protocol counters |
| Statistics | Displays protocol totals and total packet count |

## Test Results

The current automated test suite contains seven tests.

All seven tests passed during initial validation.

    Ran 7 tests
    OK

Test results may vary with future code changes.

## Testing Safety

These tests use locally constructed synthetic packets.
They do not require live network traffic or elevated privileges.
