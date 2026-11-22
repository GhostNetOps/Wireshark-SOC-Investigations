# Incident Investigation Report: Apache Tomcat Server Compromise

| Field | Details |
| :--- | :--- |
| **Platform / Lab** | CyberDefenders — Tomcat Takeover Lab |
| **Category** | Network Forensics / Web Server Intrusion |
| **Primary Tools** | Wireshark, Base64 Decoder, IP Geolocation Lookup |
| **Attack Vector** | Port & Directory Scanning → HTTP Basic Auth Brute Force → Malicious `.war` Upload → Reverse Shell |
| **Severity** | Critical |

---

## Executive Summary

The SOC team detected suspicious network activity targeting an internal **Apache Tomcat** web server on the company intranet. Forensic analysis of the captured PCAP revealed a full-chain compromise initiated from an external source IP (`14.0.0[.]120`, geolocated to China).

The threat actor began with active port scanning to identify exposed services, discovering Apache Tomcat running on TCP port `8080`. Using `gobuster/3.6`, the attacker enumerated web directories and uncovered the `/manager` administrative interface. After brute-forcing HTTP Basic Authentication with weak default credentials (`admin:tomcat`), the attacker deployed a malicious Java Web Application Archive (`JXQOZY.war`) via an HTTP `POST` request to establish an outbound reverse shell back to `14.0.0[.]120:443`.

---

## Attack Chain Summary

```text
[14.0.0[.]120] (China)
       │
       ▼  1. Active Port Scanning (TCP SYN Sweep)
   Discovered Apache Tomcat on Port 8080
       │
       ▼  2. Directory Enumeration (gobuster/3.6)
   Uncovered Administrative Panel: /manager
       │
       ▼  3. Credential Brute Force (HTTP Basic Auth)
   Authorization: Basic YWRtaW46dG9tY2F0 ──► admin:tomcat
       │
       ▼  4. Malicious WAR File Deployment (HTTP POST)
   Uploaded Payload: JXQOZY.war
       │
       ▼  5. Reverse Shell Execution & C2 Callback
   Outbound Connection ──► 14.0.0[.]120:443
```

---

## Investigation Walkthrough

### Q1. Identifying the Attacker's Source IP Address
> **Objective:** Identify the source IP address responsible for initiating port scanning and suspicious requests against the web server.

* **Wireshark Display Filter:**
  ```text
  (http.request or tls.handshake.type eq 1 or tcp.flags eq 0x0002) and !(ssdp)
  ```
* **Analysis:** Filtering for TCP `SYN` packets (`tcp.flags eq 0x0002`) alongside HTTP requests and TLS Client Hello handshakes—while excluding SSDP noise—exposed rapid connection attempts across multiple ports originating from a single external IP address.
* **Answer:** `14.0.0.120`

---

### Q2. Attacker Country of Origin
> **Objective:** Determine the geographical country associated with the threat actor's IP address.

* **Analysis:** Querying `14.0.0[.]120` against IP geolocation lookup services identified the IP range as originating from China.
* **Answer:** `China`

---

### Q3. Web Server Admin Panel Port
> **Objective:** Identify which open port discovered during the active scan hosts the Apache Tomcat administrative interface.

* **Wireshark Display Filter:**
  ```text
  (http.request or tls.handshake.type eq 1 or tcp.flags eq 0x0002) and !(ssdp)
  ```
* **Analysis:** Reviewing the filtered traffic and inspecting the Wireshark `Info` column for administrative paths and HTTP responses showed active web application and admin-panel requests directed to the standard Tomcat HTTP port.
* **Answer:** `8080`

---

### Q4. Directory Enumeration Tool
> **Objective:** Identify the automated tool used by the attacker to brute-force web directories and files.

* **Analysis:** Selecting an enumeration request targeting port `8080` and using **Follow → HTTP Stream** exposed the tool signature directly in the HTTP `User-Agent` header:
  ```http
  User-Agent: gobuster/3.6
  ```
* **Answer:** `gobuster`

---

### Q5. Discovered Administrative Directory
> **Objective:** Identify the administrative panel path uncovered during directory enumeration.

* **Analysis:** Reviewing the filtered HTTP/TCP web requests on port `8080` revealed repeated access attempts and successful hits against Apache Tomcat's built-in Manager application path.
* **Answer:** `/manager`

---

### Q6. Compromised Administrative Credentials
> **Objective:** Recover the credentials used by the attacker to authenticate into the `/manager` interface.

* **Wireshark Display Filter:**
  ```text
  http.request.method == "POST"
  ```
* **Analysis:** Following the HTTP stream of authenticated requests to `/manager` revealed an HTTP Basic Authorization header containing a Base64-encoded credential string:
  ```http
  Authorization: Basic YWRtaW46dG9tY2F0
  ```
  Decoding `YWRtaW46dG9tY2F0` from Base64 yielded the plaintext username and password.
* **Answer:** `admin:tomcat`

---

### Q7. Malicious Uploaded File
> **Objective:** Identify the malicious archive uploaded through the Tomcat Manager panel to gain remote code execution.

* **Wireshark Display Filter:**
  ```text
  http.request.method == "POST"
  ```
* **Analysis:** Inspecting HTTP `POST` multipart form-data submissions to the `/manager/html/upload` endpoint revealed the deployment of a malicious `.war` (Web Application Archive) payload designed to spawn a reverse shell.
* **Answer:** `JXQOZY.war`

---

### Q8. Reverse Shell Callback Destination
> **Objective:** Identify the attacker-controlled IP address and listening port receiving the reverse shell connection.

* **Analysis:** Inspecting outbound TCP sessions initiated from the compromised Tomcat server immediately after `JXQOZY.war` was deployed revealed a callback connection back to the attacker's host over TCP port `443` (commonly used to blend reverse shell traffic with legitimate HTTPS egress traffic).
* **Answer:** `14.0.0.120:443`

---

## Indicators of Compromise (IoCs)

| Type | Indicator (Defanged) | Context |
| :--- | :--- | :--- |
| **Source IP** | `14.0.0[.]120` | External attacker IP (China) performing scanning, exploitation, and C2 |
| **C2 Callback** | `14.0.0[.]120:443` | Reverse shell callback destination initiated by the compromised server |
| **User-Agent** | `gobuster/3.6` | Directory brute-forcing tool used against port `8080` |
| **Targeted Endpoint** | `:8080/manager` | Exposed Apache Tomcat Manager web interface |
| **Compromised Account** | `admin:tomcat` | Default/weak credentials cracked via HTTP Basic Auth brute force |
| **Malicious Artifact** | `JXQOZY.war` | Malicious Java `.war` archive uploaded for reverse shell execution |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Activity |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1595.001` | Active Scanning: Scanning IP Blocks | TCP SYN port scanning discovering port `8080` |
| **Reconnaissance** | `T1595.003` | Active Scanning: Wordlist Scanning | Directory enumeration using `gobuster/3.6` to find `/manager` |
| **Credential Access** | `T1110` | Brute Force | Brute-forcing HTTP Basic Auth on `/manager` (`admin:tomcat`) |
| **Persistence / Execution** | `T1505.003` | Server Software Component: Web Shell | Deploying malicious `JXQOZY.war` via Tomcat Manager |
| **Command and Control** | `T1095` | Non-Application Layer Protocol | Outbound raw TCP reverse shell to `14.0.0[.]120:443` |

---

## Remediation & Hardening Recommendations

1. **Immediate Containment & Eradication:** Isolate the compromised Tomcat host, terminate the active reverse shell session to `14.0.0[.]120:443`, undeploy and delete `JXQOZY.war` (along with its extracted directory in `webapps/`), and block `14.0.0[.]120` at the perimeter firewall.
2. **Restrict Tomcat Manager Access:** Disable the `/manager` application in production environments if not required, or restrict access strictly to internal administrative subnets/VPN IPs using Tomcat's `RemoteAddrValve` and firewall ACLs.
3. **Eliminate Default Credentials & Weak Auth:** Immediately rotate all credentials in `tomcat-users.xml`, enforce strong unique passwords, implement account lockout/rate-limiting (`LockOutRealm`) to stop brute-force attempts, and migrate administrative interfaces behind HTTPS/TLS.
4. **Enforce Egress Filtering:** Restrict outbound connections from intranet web servers so compromised hosts cannot initiate arbitrary outbound TCP sessions (including port `443`) to untrusted external IP addresses.
5. **Deploy Detection Rules:** Configure IDS/WAF alerting for high-volume 404 directory scans (`gobuster` user-agents), repeated HTTP `401 Unauthorized` spikes on `/manager`, and unexpected `.war` uploads.