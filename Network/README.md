# 🔍 Python Penetration Testing Tools - Network Suite

A collection of powerful Python-based network security tools for discovery, monitoring, and analysis.

## 📁 Tools Included

### 1. Network Discovery Tool (`netdiscover.py`)
Discover live hosts, open ports, and OS fingerprinting on your network.

### 2. Packet Sniffer (`sniff.py`)
Advanced packet capture and analysis tool with real-time monitoring.

### 3. WiFi Scanner (`wifi_scan.py`)
Cross-platform WiFi network discovery and security assessment.

---

# Network Discovery Tool (netdiscover.py)

A powerful Python-based network discovery and scanning tool for identifying live hosts, open ports, and operating systems on your network. Built with Scapy and Python's concurrent libraries for efficient scanning.

## Features

- **ARP Scanning**: Fast host discovery using ARP requests
- **ICMP Discovery**: Fallback ICMP echo scanning
- **Port Scanning**: Parallel TCP port scanning with customizable port lists
- **OS Detection**: Operating system fingerprinting using TTL analysis
- **Multi-threaded**: Configurable thread count for faster scans
- **Export Results**: Save scan results to text files
- **Quick Scan Mode**: Skip port scanning for rapid host discovery
- **Color-coded Output**: Clear and organized results display
- **Cross-platform**: Works on Linux, macOS, and Windows

## Prerequisites

- Python 3.6 or higher
- Root/Administrator privileges (recommended for full functionality)
- Scapy library

## Installation

### 1. Clone or Download the Script

 