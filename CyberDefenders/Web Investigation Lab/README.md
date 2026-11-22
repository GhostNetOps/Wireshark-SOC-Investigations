# Incident Investigation Report: BookWorld Web Application Compromise

| Field              | Details                                                        |
| :----------------- | :------------------------------------------------------------- |
| **Platform / Lab** | CyberDefenders — Web Investigation Lab                         |
| **Category**       | Network Forensics / Web Attack Investigation                   |
| **Primary Tools**  | Wireshark, IP Geolocation Lookup                               |
| **Attack Vector**  | SQL Injection (SQLi) → Credential Abuse → Malicious PHP Upload |
| **Severity**       | Critical                                                       |

---

## Executive Summary

An automated SOC alert triggered due to an abnormal spike in database queries and server resource utilization on **BookWorld's** e-commerce platform. Network traffic analysis of the captured PCAP revealed a multi-stage web application intrusion originating from a single external IP address (`111.224.250[.]131`, geolocated to Shijiazhuang, China).

The threat actor exploited an unsanitized `search` parameter in `search.php` using automated UNION-based SQL injection payloads to enumerate databases (`INFORMATION_SCHEMA.SCHEMATA`) and access the `customers` table within `bookworld_db`. Following database enumeration, the attacker located a hidden `/admin` directory, authenticated via an HTTP `POST` request using weak administrative credentials (`admin:admin123!`), and achieved persistence/code execution by uploading a malicious PHP script (`NVri2vhp.php`).

---

## Attack Chain Summary

```text
[111.224.250[.]131]
       │
       ▼  1. Web Enumeration & Initial SQLi Probe
   /search.php?search=book and 1=1; -- -
       │
       ▼  2. Database & Table Enumeration (UNION-Based SQLi)
   INFORMATION_SCHEMA.SCHEMATA ──► bookworld_db (customers)
       │
       ▼  3. Hidden Directory Discovery & Authentication
   /admin (HTTP POST: admin / admin123!)
       │
       ▼  4. Malicious File Upload (Web Shell / Persistence)
   NVri2vhp.php
```

---

## Investigation Walkthrough

### Q1. Identifying the Attacker's IP Address
> **Objective:** Identify the source IP address responsible for the suspicious traffic to scope the attack timeline and techniques.

* **Wireshark Display Filter:**
  ```text
  (http.request or tls.handshake.type eq 1) and !(ssdp)
  ```
* **Analysis:** Filtering for outbound/inbound web requests while excluding noisy SSDP traffic isolated the active HTTP sessions. Traffic inspection showed a single external IP address driving the anomalous volume of web requests against the server.
* **Answer:** `111.224.250.131`

---

### Q2. Attacker Geolocation
> **Objective:** Determine the geographical origin city of the threat actor's IP address.

* **Analysis:** Querying `111.224.250[.]131` against IP geolocation intelligence sources traced the address to China.
* **Answer:** `Shijiazhuang` *(China)*

---

### Q3. Vulnerable PHP Script Identification
> **Objective:** Identify the vulnerable backend PHP script targeted during initial exploitation.

* **Wireshark Display Filter:**
  ```text
  http contains ".php"
  ```
* **Analysis:** Reviewing HTTP traffic referencing `.php` endpoints revealed repeated malformed query strings targeting `search.php`.
* **Answer:** `search.php`

---

### Q4. First SQL Injection Attempt (Complete Decoded Request URI)
> **Objective:** Establish the start of the exploitation timeline by capturing the first SQLi payload.

* **Observed Raw Request:**
  ```http
  GET /search.php?search=book%20and%201=1;%20--%20- HTTP/1.1
  ```
* **Analysis:** The attacker injected a classic boolean tautology (`and 1=1; -- -`) into the `search` parameter to test whether input was sanitized before reaching the backend SQL parser.
* **Answer (URL-Decoded):**
  ```text
  /search.php?search=book and 1=1; -- -
  ```

---

### Q5. Database Enumeration Request URI (Decoded)
> **Objective:** Extract the complete decoded URI used to dump available databases from the web server.

* **Wireshark Display Filter:**
  ```text
  http.request.uri contains "SCHEMATA"
  ```
* **Observed Raw Request:**
  ```http
  GET /search.php?search=book%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178766271%2CJSON_ARRAYAGG%28CONCAT_WS%280x7a76676a636b%2Cschema_name%29%29%2C0x7176706a71%29%20FROM%20INFORMATION_SCHEMA.SCHEMATA--%20- HTTP/1.1
  ```
* **Analysis:** The attacker used an automated `UNION ALL SELECT` payload (characteristic of `sqlmap` hex marker delimiters `0x7178766271` / `0x7176706a71`) against `INFORMATION_SCHEMA.SCHEMATA` to aggregate and exfiltrate schema names in JSON format.
* **Answer (URL-Decoded):**
  ```text
  /search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -
  ```

---

### Q6. Compromised User Data Table
> **Objective:** Identify the database table storing customer/user records to assess breach impact.

* **Wireshark Display Filter:**
  ```text
  http contains "bookworld_db"
  ```
* **Analysis:** Inspecting HTTP responses tied to the `bookworld_db` schema exposed the database tables queried by the attacker, confirming access to the table storing user information.
* **Answer:** `customers`

---

### Q7. Discovered Hidden Directory
> **Objective:** Identify the non-public web directory uncovered by the attacker.

* **Analysis:** Using **Follow → HTTP Stream** on the sessions identified in Q6 revealed subsequent attacker navigation into a restricted administrative path.
* **Answer:** `admin`

---

### Q8. Compromised Administrative Credentials
> **Objective:** Determine the credentials used to authenticate into the administrative portal.

* **Wireshark Display Filter:**
  ```text
  http.request.method == "POST"
  ```
* **Analysis:** Filtering for HTTP `POST` submissions located the authentication request sent to the `/admin` login form, exposing the cleartext credentials submitted in the request body.
* **Answer:**
  * **Username:** `admin`
  * **Password:** `admin123!`

---

### Q9. Malicious Uploaded Script
> **Objective:** Confirm whether the attacker established deeper server access via file upload.

* **Wireshark Display Filter:**
  ```text
  http contains "upload"
  ```
* **Analysis:** Inspecting HTTP streams containing upload activity revealed that after authenticating to the admin panel, the attacker uploaded a randomly named PHP payload to gain persistent remote access on the web server.
* **Answer:** `NVri2vhp.php`

---

## Indicators of Compromise (IoCs)

| Type | Indicator (Defanged) | Context |
| :--- | :--- | :--- |
| **Source IP** | `111.224.250[.]131` | External attacker IP (Shijiazhuang, China) |
| **Vulnerable Endpoint** | `/search.php` | Entry point vulnerable to UNION-based SQL injection |
| **Targeted Path** | `/admin` | Exposed administrative login panel |
| **Compromised Account** | `admin` (`admin123!`) | Weak credentials used for unauthorized login |
| **Malicious File** | `NVri2vhp.php` | Uploaded PHP script / potential web shell |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Activity |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1190` | Exploit Public-Facing Application | SQL injection against `search.php` |
| **Collection** | `T1213` | Data from Information Repositories | Dumping `INFORMATION_SCHEMA.SCHEMATA` and `bookworld_db.customers` |
| **Initial Access / Privilege Escalation** | `T1078` | Valid Accounts | Authenticating to `/admin` using `admin:admin123!` |
| **Persistence** | `T1505.003` | Server Software Component: Web Shell | Uploading `NVri2vhp.php` via the admin interface |

---

## Remediation & Hardening Recommendations

1. **Patch SQL Injection (`search.php`):** Refactor all database queries to use parameterized queries (prepared statements via PDO or MySQLi) and enforce strict server-side input validation.
2. **Immediate Containment:** Block `111.224.250[.]131` at the perimeter firewall/WAF, isolate the web server, remove `NVri2vhp.php`, and audit the filesystem and web logs for secondary persistence mechanisms.
3. **Harden Administrative Access:** Rotate all administrative and database credentials immediately, enforce strong password complexity and MFA, and restrict `/admin` access via VPN or IP allowlisting.
4. **Secure File Uploads:** Implement strict server-side file type/MIME validation, store uploaded files outside the web root, and disable PHP execution in upload directories.
5. **Enforce Encryption in Transit:** Migrate all login and administrative endpoints to HTTPS/TLS so credentials and session tokens are never transmitted in cleartext.