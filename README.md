# Python Network IDS

A lightweight Python-based Network Intrusion Detection System (NIDS) that captures network packets and scans their payloads for suspicious signatures.

## Features

- Raw packet sniffing using Python sockets (Linux)
- Scapy-based packet capture and parsing
- Signature-based payload analysis
- Detects:
  - SQL Injection attempts
  - Directory Traversal
  - Reverse Shell attempts
  - Suspicious User-Agents (sqlmap, nikto, w3af)
- Graceful shutdown with `Ctrl+C`
- Modular design: sniffer, analyzer, capturer, parser

## Requirements

- Python 3.8+
- `scapy` (for the Scapy-based capturer)
- Linux for raw socket mode (`AF_PACKET`)
- Root / administrator privileges for packet capture

## Installation

```bash
git clone https://github.com/yourusername/python-network-ids.git
cd python-network-ids
pip install scapy
