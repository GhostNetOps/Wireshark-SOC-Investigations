### Case 5: `Case-05-LummaStealer/README.md`
```markdown
# 🚨 Incident Report: Lumma In The Room-Ah

* **Incident Date:** 2026-01-31
* **Lead Analyst:** (`GhostNetOps`)
* **Malware Family:** Lumma Stealer (Information Stealer)

## 📋 Executive Summary
Network telemetry captured suspicious DNS requests resolving to known malicious domains associated with the **Lumma Stealer** malware family. The malware successfully initiated C2 beacons to exfiltrate host data, originating from a known threat actor IP.

## 🖥️ Victim Asset Profile

| Attribute | Extracted Value | Protocol Source |
| :--- | :--- | :--- |
| **Internal IPv4** | `10.1.28.58` | IPv4 Header |
| **MAC Address** | `00:21:5d:c8:0e:f2` | Ethernet II Frame |
| **Windows Hostname** | `DESKTOP-ES9F3ML` | Kerberos AS-REQ (`CNameString`) |
| **AD User Account** | `gwyatt` | Kerberos AS-REQ (`CNameString`) |
| **Employee Full Name**| Gabriel Wyatt | DCE/RPC (`samr`) |

## 🛡️ Threat Indicators (IOCs)

| Indicator Type | Defanged Value | Protocol / Context |
| :--- | :--- | :--- |
| **C2 Domain** | `holidayforever[.]cc` | Lumma Stealer DNS Query |
| **C2 Domain** | `communicationfirewall-security[.]cc` | Lumma Stealer DNS Query |
| **Malicious IP** | `153.92.1[.]49` | Threat Origin / Delivery |

## 🛠️ TShark Extraction Log
```bash
# Filtering for malicious DNS resolutions tied to the Lumma infection
$ tshark -r lumma.pcap -Y "dns.qry.name contains cc" -T fields -e dns.qry.name | sort | uniq
holidayforever.cc
communicationfirewall-security.cc