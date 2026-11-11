### Case 3: `Case-03-Natureforce/README.md`
```markdown
# 🚨 Incident Report: Natureforce

* **Incident Date:** 2026-10-01
* **Lead Analyst:** Ali (`GhostNetOps`)
* **Malware Family:** CNCmachineRMS RAT 

## 📋 Executive Summary
Network telemetry captured a rogue Windows executable (`.exe`) being delivered over a non-standard port (TCP 9000). Object extraction from the raw TCP stream confirmed the payload as the CNCmachineRMS Remote Access Trojan.

## 🖥️ Victim Asset Profile

| Attribute | Extracted Value | Protocol Source |
| :--- | :--- | :--- |
| **Internal IPv4** | `10.10.1.128` | IPv4 Header |
| **MAC Address** | `00:22:fb:ec:7e:e7` | Ethernet II Frame |
| **Windows Hostname** | `DESKTOP-4VGYQX7` | Kerberos AS-REQ (`CNameString`) |
| **AD User Account** | `bdiaz` | Kerberos AS-REQ (`CNameString`) |

## 🛡️ Payload Forensics & IOCs

| Indicator Type | Defanged Value |
| :--- | :--- |
| **Source Delivery IP** | `107.175.82[.]242:9000` |
| **Payload SHA-256 Hash** | `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061` |

## 🛠️ Extraction Methodology
The malicious executable was carved directly from the packet capture using Wireshark's `Export Objects` functionality on the TCP/HTTP stream originating from `107.175.82.242`. The exported binary was hashed via SHA-256 to verify against threat intelligence platforms.