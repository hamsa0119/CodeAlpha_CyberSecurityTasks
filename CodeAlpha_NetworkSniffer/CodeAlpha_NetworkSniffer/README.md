# Basic Network Sniffer

CodeAlpha Cyber Security Internship - Task 1

A Python tool that captures live network packets with Scapy and shows
how data flows through the network.

## Features
- Source and destination IP addresses with ports
- Protocol detection (TCP / UDP / ICMP)
- Payload preview (first 50 bytes)
- Timestamp for every packet

## Requirements
- Python 3
- Scapy: `pip install scapy`
- Windows: Npcap (https://npcap.com)

## How to run
```
pip install scapy
python sniffer.py
```
Run the terminal as Administrator (Windows) or use `sudo` (Linux/Mac).
Generate traffic with `ping google.com` or by opening a website.

## What I learned
- TCP: reliable connections, used for web browsing (HTTP/HTTPS)
- UDP: fast and connectionless, used for DNS and streaming
- ICMP: control messages such as ping
- Data flows from the source device through the router to the destination server

## Note
Use only on your own network. Capturing other people's traffic without permission is illegal.
