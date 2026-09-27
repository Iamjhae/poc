# Xerox Printer Target: 13.13.1.112

## Target Summary

| Field         | Value                |
|---------------|----------------------|
| IP            | 13.13.1.112          |
| Severity Tier | Critical             |
| Status        | Eligible             |
| Expiry        | Sep 15, 2026         |
| Resolved      | 0%                   |

## Known Issues (Already Reported - Do NOT Re-report)

- **Medium** — Unauthenticated PJL and PS Access on Raw Print Port 9100
- **Medium** — Unauthenticated Information Disclosure via eSCL ScannerCapabilities
- **Low** — Internal Hostname Disclosure via TLS Certificate

---

## Phase 1: Passive Reconnaissance

### 1.1 Service Enumeration
```bash
# Full TCP port scan (top 10000)
nmap -sS -sV -p- --open -T4 -oN nmap_full_tcp.txt 13.13.1.112

# UDP scan (common printer ports)
nmap -sU -p 161,162,631,9100,9101,9102,5353 -sV -oN nmap_udp.txt 13.13.1.112

# Service version + scripts
nmap -sV -sC -p- -oN nmap_scripts.txt 13.13.1.112
```

### 1.2 Web Interface Discovery
```bash
# HTTP/HTTPS enumeration
curl -sk https://13.13.1.112/ -o /dev/null -w "%{http_code} %{redirect_url}\n"
curl -sk http://13.13.1.112/ -o /dev/null -w "%{http_code} %{redirect_url}\n"

# Identify web server and tech stack
curl -sIk https://13.13.1.112/
curl -sIk http://13.13.1.112/

# Directory/path brute-force (printer-specific wordlist)
gobuster dir -u https://13.13.1.112 -w /path/to/printer-paths.txt -k --status-codes 200,301,302,401,403
```

### 1.3 Printer-Specific Protocols
```bash
# SNMP enumeration (community strings)
snmpwalk -v2c -c public 13.13.1.112
snmpwalk -v2c -c public 13.13.1.112 1.3.6.1.2.1.1   # System info
snmpwalk -v2c -c public 13.13.1.112 1.3.6.1.2.1.25   # Host resources

# IPP enumeration
ipptool -tv https://13.13.1.112/ipp/print get-printer-attributes.test

# mDNS/DNS-SD
avahi-browse -art | grep 13.13.1.112

# LDAP (if 389/636 open)
ldapsearch -x -H ldap://13.13.1.112 -b "" -s base namingContexts
```

### 1.4 Firmware Analysis
```
# Download firmware from support.xerox.com for the identified model
# Tools: binwalk, firmware-mod-kit, strings, ghidra
binwalk -e firmware.bin
strings firmware.bin | grep -iE "password|secret|key|token|admin"
```

---

## Phase 2: Attack Surface Mapping

### 2.1 Common Xerox Printer Ports & Services

| Port  | Service            | Attack Vector                          |
|-------|--------------------|----------------------------------------|
| 80    | HTTP (EWS)         | Auth bypass, XSS, CSRF, RCE           |
| 443   | HTTPS (EWS)        | Same as HTTP + TLS misconfigs          |
| 631   | IPP                | Unauthenticated printing, info leak    |
| 9100  | Raw Print (PJL/PS) | **Known - out of scope**               |
| 161   | SNMP               | Community string abuse, info disclosure|
| 515   | LPD                | Print job manipulation                 |
| 21    | FTP                | Anonymous access, file exfil           |
| 22    | SSH                | Weak creds (no brute force)            |
| 23    | Telnet             | Cleartext comms, command injection     |
| 5353  | mDNS               | Service discovery, info leak           |
| 389   | LDAP               | Credential harvesting                  |

### 2.2 Xerox EWS (Embedded Web Server) Focus Areas

- `/header.php`, `/properties/`, `/config/`, `/status/`
- Authentication pages and session management
- Configuration export/import functionality
- Address book / contact list access
- Firmware update mechanism
- Certificate management
- Clone file functionality
- Network configuration pages

---

## Phase 3: Vulnerability Hunting (Priority Order)

### 3.1 Critical — Remote Code Execution (RCE)
```
- Firmware update mechanism abuse (unsigned firmware upload)
- Command injection in web interface parameters
- PostScript/PJL command injection via print jobs
- Deserialization vulnerabilities in web services
- Buffer overflows in custom web server
- SOAP/XML injection in web services endpoints
```

### 3.2 Critical — Authentication Bypass
```
- Default credentials (admin/1111, admin/admin — check, don't brute force)
- Session fixation / session prediction
- Authentication bypass via direct URL access
- Cookie manipulation
- IDOR on user/admin endpoints
```

### 3.3 High — Sensitive Data Exposure
```
- Cached print jobs accessible without auth
- Address book / LDAP credential extraction
- SNMP write community string exposure
- Configuration backup download (clone files often contain creds)
- Debug/diagnostic pages leaking internal data
```

### 3.4 High — Network Pivot / Lateral Movement
```
- SSRF via fax/scan-to-email/scan-to-network features
- SMB relay through scan-to-folder
- LDAP injection via address book lookups
- DNS rebinding attacks
```

### 3.5 High — Firmware Manipulation
```
- Unsigned firmware upload
- Downgrade attack (install older vulnerable firmware)
- Persistent implant via firmware modification
```

### 3.6 Medium — Cross-Site Scripting (XSS)
```
- Stored XSS in device name, contact book, job names
- Reflected XSS in error pages, search parameters
- XSS via print job metadata displayed in job log
```

### 3.7 Medium — CSRF
```
- Configuration changes without CSRF tokens
- Password reset via CSRF
- Factory reset via CSRF
```

---

## Phase 4: Xerox-Specific Attack Techniques

### 4.1 Clone File Attack
```
Xerox printers allow configuration export as "clone files".
If accessible without auth, these may contain:
- LDAP bind credentials
- SMB share credentials
- SMTP authentication details
- SNMP community strings
- WiFi PSK
```

### 4.2 PostScript Sandbox Escape
```
PostScript is a Turing-complete language. Exploit paths:
- File system access via PS operators
- Memory read/write primitives
- Escape PS interpreter sandbox
- Reference: PRET (Printer Exploitation Toolkit)
```

### 4.3 PJL Directory Traversal
```
PJL commands may allow file system traversal:
@PJL FSDOWNLOAD ...
@PJL FSDIRLIST NAME="0:\..\" ...
@PJL FSQUERY NAME="0:\..\etc\passwd" ...
```

### 4.4 SNMP Write Abuse
```
If SNMP write community string is accessible:
- Change sysContact/sysLocation to exfiltrate data
- Modify network config (DNS, gateway) for MitM
- Disable security features
```

### 4.5 Web Services (SOAP) Exploitation
```
Xerox printers expose SOAP-based web services.
Test for:
- XXE in SOAP XML parser
- SOAP injection
- WSDL enumeration for hidden functions
- Unauthenticated admin SOAP calls
```

---

## Phase 5: Tools Arsenal

| Tool            | Purpose                                      |
|-----------------|----------------------------------------------|
| nmap            | Port scanning, service enumeration            |
| PRET            | Printer exploitation (PJL, PS, PCL)           |
| Burp Suite      | Web interface testing                         |
| snmpwalk/snmpset| SNMP enumeration and exploitation             |
| Wireshark       | Traffic analysis, credential capture          |
| binwalk/Ghidra  | Firmware reverse engineering                  |
| ipptool         | IPP protocol testing                          |
| nuclei          | Automated vuln scanning (custom templates)    |
| ffuf/gobuster   | Web path discovery                            |
| curl            | Manual HTTP request crafting                  |

---

## Reporting Checklist

For each finding, prepare:
- [ ] Vulnerability description and threat scenario
- [ ] Step-by-step reproduction
- [ ] Proof of exploitability (screenshots/video)
- [ ] Impact assessment (what an attacker gains)
- [ ] CVSSv3 vector and score
- [ ] Affected parameters and payloads

---

## Notes

- Start unauthenticated — request creds only if needed later
- Avoid: brute forcing, DoS, shell uploads, data exfiltration
- Firmware available at support.xerox.com
- Focus on findings NOT detectable by automated scanners
- Chain vulnerabilities for higher impact when possible
