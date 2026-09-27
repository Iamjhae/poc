# Deep Recon Plan: Xerox Printer 13.13.1.112

**Program:** Xerox Bug Bounty (HackerOne Private)
**Target:** 13.13.1.112 (added Sep 15, 2026 - 0% resolved, fresh target)
**Asset Type:** Xerox Printer (IP Address)
**Severity Eligible:** Critical

## Known Out-of-Scope Issues (13.13.1.112)

| Severity | Issue |
|----------|-------|
| Medium | Unauthenticated PJL and PS Access on Raw Print Port 9100 |
| Medium | Unauthenticated Information Disclosure via eSCL ScannerCapabilities |
| Low | Internal Hostname Disclosure via TLS Certificate |

## Global Out-of-Scope

- Physical attacks
- Automated scanner findings (Nessus/Qualys-level)
- Known vulnerable libraries without working PoC
- CSV injection without demonstrated impact
- SSL/TLS config best practices (missing HSTS, weak ciphers alone)
- Banner/version disclosure alone
- Zero-days with official patch < 1 month old

## Recon Phases

### Phase 1: Port Scan & Service Detection
Full TCP + targeted UDP scan. Fingerprint all services. Identify non-standard ports.

### Phase 2: Web Interface Enumeration
Directory brute-force with Xerox-specific wordlist. Header analysis. Hidden endpoints.

### Phase 3: SNMP Enumeration
Community string discovery. Full MIB walk. Device fingerprinting. Network topology extraction.

### Phase 4: Deep Service Enumeration
IPP, LPD, mDNS/DNS-SD, WSD, UPnP, FTP, Telnet, SSH, SOAP/XML web services.

### Phase 5: Firmware & Model Identification
Extract exact model and firmware version. Map to known CVEs. Download firmware for offline analysis.

### Phase 6: Authentication Testing
Default creds (not brute force). Unauthenticated access to sensitive endpoints. HTTP method testing. Session management analysis.

### Phase 7: Vulnerability Assessment
XSS, SSRF, path traversal, command injection, SNMP write access. Deep SSL/TLS exploit checks.

### Phase 8: Lateral Movement Recon
ARP/routing table extraction. Stored credential harvesting. Address book extraction. Internal host discovery.

### Phase 9: Print Protocol Exploitation
PJL/PS via non-9100 vectors (IPP, LPD, web upload). Job history disclosure. PostScript injection.

## High-Value Attack Scenarios (from scope)

1. **Extract sensitive data** - Print job history, address books, stored credentials
2. **Botnet conversion** - RCE + persistence via firmware modification
3. **Network pivot** - Use printer as launching pad into enterprise network
4. **Firmware alteration** - Modify firmware to maintain access or cause DoS
5. **Enterprise monitoring** - Intercept print/scan jobs, email configs
6. **Full device takeover** - RCE with root/admin on embedded OS

## Usage

```bash
cd recon/scripts
chmod +x *.sh

# Run all phases
./00_run_all.sh

# Run specific phase
./00_run_all.sh 3   # SNMP only
```

Results are saved to `recon/results/` organized by phase.
