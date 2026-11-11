### Case 1: `CCase-01-EasyAs123/README.md`
```markdown
# 🚨 Incident Report: Easy As 123

* **Incident Date:** 2026-02-28
* **Lead Analyst:** (`GhostNetOps`)
* **Malware Family:** NetSupport Manager RAT

## 📋 Executive Summary
SIEM alerts flagged suspicious outbound traffic over TCP port 443. PCAP analysis revealed that port 443 was being abused to transmit unencrypted HTTP POST requests rather than standard TLS traffic. The compromised Active Directory client initiated a Command and Control (C2) beacon to a known NetSupport RAT infrastructure.

## 🖥️ Victim Asset Profile

| Attribute | Extracted Value | Protocol Source |
| :--- | :--- | :--- |
| **Internal IPv4** | `10.2.28.88` | IPv4 Header |
| **MAC Address** | `00:19:d1:b2:4d:ad` | Ethernet II Frame |
| **Windows Hostname** | `DESKTOP-TEYQ2NR` | Kerberos AS-REQ (`CNameString`) |
| **AD User Account** | `brolf` | Kerberos AS-REQ (`CNameString`) |
| **Employee Full Name**| Becka Rolf | DCE/RPC (`samr`) |

## 🛠️ TShark Extraction Log
Instead of manual GUI filtering, the following CLI commands were used to parse the PCAP and extract the victim identity:

```bash
# Extracting Hostname and User Account via Kerberos
$ tshark -r easy_as_123.pcap -Y "kerberos.CNameString and ip.src==10.2.28.88" -T fields -e kerberos.CNameString | sort | uniq
DESKTOP-TEYQ2NR$
brolf