### Case 4: `Case-04-FirstToLast/README.md`
```markdown
# 🚨 Incident Report: First To Last

* **Incident Date:** 2026-08-09
* **Lead Analyst:** Ali (`GhostNetOps`)
* **Malware Family:** FormBook / XLoader

## 📋 Executive Summary
A large volume of IDS alerts (ET MALWARE FormBook CnC Checkin) triggered across the `172.16.8.0/24` subnet. Despite multiple IPs appearing in the alert logs, forensic analysis isolated the actual infected host generating the patterned HTTP POST and GET C2 beacons.

## 🖥️ Victim Asset Profile

| Attribute | Extracted Value | Protocol Source |
| :--- | :--- | :--- |
| **Internal IPv4** | `172.16.8.49` | IPv4 Header |
| **MAC Address** | `00:12:f0:28:d4:34` | Ethernet II Frame |
| **Windows Hostname** | `DESKTOP-5NLV63K` | Kerberos AS-REQ (`CNameString`) |
| **AD User Account** | `rvance` | Kerberos AS-REQ (`CNameString`) |
| **Employee Full Name**| Raymond Vance | DCE/RPC (`samr`) |

## 🛠️ TShark Extraction Log
```bash
# Identifying the specific user account associated with the beaconing IP
$ tshark -r first_to_last.pcap -Y "kerberos.CNameString and ip.addr==172.16.8.49" -T fields -e kerberos.CNameString | grep -v "\$" | head -n 1
rvance