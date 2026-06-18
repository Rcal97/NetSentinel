# NetSentinel 🛡️

> A lightweight Network Intrusion Detection System (NIDS) written in modern C++17.

![C++](https://img.shields.io/badge/C++-17-00599C?style=flat&logo=cplusplus&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-3.20+-064F8C?style=flat&logo=cmake&logoColor=white)
![libpcap](https://img.shields.io/badge/libpcap-1.10-informational?style=flat)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=flat)

---

## Overview

NetSentinel is a command-line Network Intrusion Detection System that captures live network traffic, analyses packets in real time, and raises alerts when suspicious patterns are detected. The project is designed to showcase clean C++17 systems programming, object-oriented architecture, and the application of classic software design patterns in a security context.

---

## Features

- **Live packet capture** via libpcap on any available network interface
- **Protocol parsing** for Ethernet, IP, TCP, UDP, and ICMP headers
- **Rule-based detection engine** with configurable rules (port scan detection, ICMP flood, SYN flood, blacklisted IPs)
- **Alert system** with console output and log file
- **Modular, extensible architecture** based on GoF design patterns

---

## Architecture

The codebase is organised around four core components:

```
NetSentinel/
├── CMakeLists.txt
├── README.md
├── include/
│   ├── PacketCapture.h       # Interface for packet capture
│   ├── PacketAnalyzer.h      # Packet parsing and dissection
│   ├── RuleEngine.h          # Rule engine (Strategy pattern)
│   └── AlertManager.h        # Alert dispatching (Observer pattern)
├── src/
│   ├── main.cpp
│   ├── PacketCapture.cpp
│   ├── PacketAnalyzer.cpp
│   ├── RuleEngine.cpp
│   └── AlertManager.cpp
└── tests/
```

### Design Patterns

| Pattern | Where | Purpose |
|---|---|---|
| **Strategy** | `RuleEngine` | Swap detection rules at runtime without changing the engine |
| **Observer** | `AlertManager` | Decouple alert producers from alert consumers (console, log file) |
| **Factory** | `RuleEngine` | Instantiate concrete rule objects from configuration |

---

## Detection Rules

| Rule | Description |
|---|---|
| Port Scan Detection | Flags a source IP that contacts more than N distinct ports in a time window |
| SYN Flood Detection | Flags a high rate of TCP SYN packets from a single source |
| ICMP Flood Detection | Flags an excessive number of ICMP echo requests |
| Blacklist | Drops and alerts on traffic from/to a configurable list of IPs |

---

## Tech Stack

| Tool | Purpose |
|---|---|
| C++17 | Core language |
| libpcap | Low-level packet capture |
| CMake 3.20+ | Build system |
| g++ 13 | Compiler |

---

## Build & Run

### Prerequisites

```bash
sudo apt install cmake libpcap-dev g++ -y
```

### Build

```bash
git clone https://github.com/Rcal97/NetSentinel
cd NetSentinel
mkdir build && cd build
cmake ..
make
```

### Run

```bash
sudo ./NetSentinel -i eth0        # capture on interface eth0
sudo ./NetSentinel -i wlan0       # capture on Wi-Fi
sudo ./NetSentinel --list         # list available interfaces
```

> **Note:** Root privileges are required for raw packet capture.

---

## Roadmap

- [x] Project structure and CMake setup
- [ ] PacketCapture — libpcap integration
- [ ] PacketAnalyzer — Ethernet/IP/TCP/UDP/ICMP parsing
- [ ] RuleEngine — Strategy pattern + first detection rules
- [ ] AlertManager — Observer pattern + console/log output
- [ ] Configuration file support (JSON/INI)
- [ ] Statistics summary on exit

---

## Author

**Raffaele Calcagno**  
[rcal97.github.io](https://rcal97.github.io) · [linkedin.com/in/raffaele-calcagno](https://www.linkedin.com/in/raffaele-calcagno) · [github.com/Rcal97](https://github.com/Rcal97)
