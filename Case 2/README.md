### Case 2: `Case-02-Kongtuke/README.md`
```markdown
# 🚨 Incident Report: Kongtuke Rebuke!

* **Incident Date:** 2026-09-11
* **Lead Analyst:** Ali (`GhostNetOps`)
* **Malware Family:** Kongtuke ClickFix (Social Engineering / AD Discovery)

## 📋 Executive Summary
An internal workstation was compromised via a "ClickFix" social engineering vector (fake verification page). Following the initial compromise, the malware initiated staging infrastructure downloads and performed internal Active Directory discovery queries (LDAP/SMB). 

## 🖥️ Victim Asset Profile

| Attribute | Extracted Value | Protocol Source |
| :--- | :--- | :--- |
| **Internal IPv4** | `10.9.11.135` | IPv4 Header |
| **MAC Address** | `08:d4:0c:7a:29:1e` | Ethernet II Frame |
| **Windows Hostname** | `DESKTOP-6T17ZFM` | Kerberos AS-REQ (`CNameString`) |
| **AD User Account** | `gmcdowell` | Kerberos AS-REQ (`CNameString`) |
| **Employee Full Name**| Gabriel McDowell | DCE/RPC (`samr`) |

## 🛠️ TShark Extraction Log
```bash
# Correlating the infected IP to its physical MAC address
$ tshark -r kongtuke.pcap -Y "ip.src==10.9.11.135" -T fields -e eth.src -c 1
08:d4:0c:7a:29:1e