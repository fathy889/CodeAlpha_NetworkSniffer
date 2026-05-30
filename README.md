# 🔍 CodeAlpha Network Sniffer
### Cyber Security Internship — Task 1

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.7.0-green?style=flat)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple?style=flat&logo=linux)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)

---

## 📌 Description

A Python-based network packet sniffer built with **Scapy**.  
It captures live network traffic and analyzes packets in real time,  
displaying useful information such as source/destination IPs, MAC addresses,  
protocols, ports, TCP flags, DNS queries, HTTP requests, and raw payloads.

---

## ✨ Features

- 🟢 **Multi-Protocol Support** — TCP, UDP, ICMP, DNS, HTTP, ARP
- 🔵 **Layer 2 Analysis** — MAC addresses from Ethernet frames
- 🟡 **Layer 3/4 Analysis** — IP addresses, ports, TCP flags
- 🟣 **DNS Inspection** — Captures DNS queries and responses
- 🔴 **HTTP Sniffing** — Detects HTTP methods, hosts, paths
- 📊 **Live Statistics** — Protocol breakdown summary after capture
- 💾 **Logging Support** — Save output to a text file
- 🎨 **Colored Output** — Clean terminal UI with Colorama

---

## 🛠️ Requirements

```bash
sudo apt install python3-scapy python3-colorama -y
```

---

## 🚀 Usage

```bash
# Basic capture on eth0
sudo python3 network_sniffer.py -i eth0

# Capture 50 packets only
sudo python3 network_sniffer.py -i eth0 -c 50

# Filter HTTP traffic only
sudo python3 network_sniffer.py -i eth0 -f "tcp port 80"

# Filter DNS traffic only
sudo python3 network_sniffer.py -i eth0 -f "udp port 53"

# Save output to file
sudo python3 network_sniffer.py -i eth0 --log capture.txt
```

---

## 📡 Sample Output

```
╔══════════════════════════════════════════════════════════╗
║   🔍  CodeAlpha Network Sniffer                          ║
║   Cyber Security Internship — Task 1                     ║
╚══════════════════════════════════════════════════════════╝

[   1] 09:43:46.284 [ DNS ] 70B
  SRC 10.0.2.15:36752  →  DST 10.0.2.3:53
  MAC 08:00:27:63:b0:05 → 52:55:0a:00:02:03
  INFO  Query → google.com
────────────────────────────────────────────────────────────
[   2] 09:43:46.366 [ ICMP] 98B
  SRC 10.0.2.15  →  DST 172.217.168.142
  MAC 08:00:27:63:b0:05 → 52:55:0a:00:02:02
  INFO  Echo Request
────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════
  📊  CAPTURE SUMMARY
════════════════════════════════════════════════════════════
  Total Packets        69

  ICMP                 56  ████████████████████████████████
  DNS                   6  ██████
  ARP                   4  ████
  OTHER                 3  ███
```

---

## 🔍 Protocol Analysis

| Protocol | What it captures |
|----------|-----------------|
| **DNS**  | Domain queries & resolved IPs |
| **ICMP** | Ping requests & replies |
| **TCP**  | Connections, flags (SYN, ACK, FIN, RST) |
| **UDP**  | Connectionless traffic |
| **HTTP** | Methods, hosts, paths (unencrypted traffic) |
| **ARP**  | MAC-to-IP resolution (useful for ARP spoofing detection) |

---

## 📁 Project Structure

```
CodeAlpha_NetworkSniffer/
├── network_sniffer.py    # Main sniffer script
└── README.md             # Project documentation
```

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes only**.  
Use it only on networks you own or have explicit permission to test.  
Unauthorized packet sniffing is illegal and unethical.

---

## 👤 Author

**Fathy WAEL** — CodeAlpha Cyber Security Intern  
GitHub: [@fathy889](https://github.com/fathy889)

---

*CodeAlpha Cyber Security Internship — Task 1*
