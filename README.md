# 🛡️ SOC Packet Forensics & Incident Response Playbook

![Role](https://img.shields.io/badge/Role-Tier_2_SOC_Analyst-blue?style=for-the-badge)
![Tools](https://img.shields.io/badge/Tools-Wireshark_%7C_TShark-orange?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Threat_Hunting_%7C_Malware_Analysis-success?style=for-the-badge)

This repository serves as a live playbook of network forensic investigations and incident response reports. All traffic analysis is performed on raw `.pcap` files capturing real-world malware infections, Active Directory compromises, and Command & Control (C2) beaconing.

* **Lead Investigator:** (`GhostNetOps`)
* **Data Source:** [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)
* **Methodology:** GUI analysis via Wireshark coupled with `TShark` CLI automation for IOC extraction.

> **⚠️ Notice:** Raw `.pcap` and `.exe` payload files are intentionally excluded from this repository via `.gitignore` to prevent the distribution of live malware. All Indicators of Compromise (IOCs) are defanged.

## 📂 Case Index

| Case Directory | Date | Threat Profile / Malware Family | Core Forensic Skills Demonstrated |
| :--- | :--- | :--- | :--- |
| **`Case-01-EasyAs123/`** | 2026-02-28 | NetSupport Manager RAT | Kerberos/SAMR Parsing, Port Evasion (HTTP over 443) |
| **`Case-02-Kongtuke/`** | 2026-09-11 | Kongtuke ClickFix | TLS Handshake Analysis, HTTPS C2 Tracking |
| **`Case-03-Natureforce/`** | 2026-10-01 | CNCmachineRMS RAT | TCP Stream Carving, Object Extraction, Payload Hashing |
| **`Case-04-FirstToLast/`** | 2026-08-09 | FormBook / XLoader | Multi-Host Triage, Patterned HTTP C2 Beacons |
| **`Case-05-LummaStealer/`** | 2026-01-31 | Lumma Stealer (Info-Stealer) | DNS Query Isolation, Info-Stealer Domain Defanging |