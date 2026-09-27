#!/bin/bash
# Phase 6: Authentication Testing & Bypass Attempts
# Scope: "You are strongly encouraged to first exploit the printer as an
#         unauthenticated user - that is, without requesting any account from us."
# NOTE: Do NOT brute force credentials (program rule)

TARGET="13.13.1.112"
OUTDIR="../results/06_auth"
mkdir -p "$OUTDIR"

echo "[*] Phase 6: Authentication & Access Control Testing - $TARGET"

###############################################################################
# 6a. Default credential check (NOT brute force - known defaults only)
###############################################################################
echo "[+] Testing Xerox default credentials (not brute forcing)..."

# Xerox well-known defaults (public documentation)
declare -A DEFAULTS=(
  ["admin"]="1111"
  ["admin"]="admin"
  ["admin"]=""
  [""]=""
  ["guest"]="guest"
  ["user"]="user"
)

for PROTO in http https; do
  # Try common Xerox login endpoints
  for LOGIN_PATH in "/login" "/PRESENTATION/LOGIN" "/security/login.dhtml" "/webglue/content?c=login"; do
    echo "  Testing $PROTO://$TARGET$LOGIN_PATH"

    # GET the login page first to find form fields and CSRF tokens
    LOGINPAGE=$(curl -skL -c "$OUTDIR/cookies.txt" --connect-timeout 5 \
      "$PROTO://$TARGET$LOGIN_PATH" 2>/dev/null)

    # Extract form action and hidden fields
    echo "$LOGINPAGE" | grep -ioP '(action|name|value|csrf|token)[="][^"]*"' \
      > "$OUTDIR/login_form_${PROTO}.txt" 2>/dev/null

    # Test admin:1111 (most common Xerox default)
    curl -skL -b "$OUTDIR/cookies.txt" -c "$OUTDIR/cookies.txt" \
      --connect-timeout 5 \
      -d "username=admin&password=1111" \
      "$PROTO://$TARGET$LOGIN_PATH" \
      -o "$OUTDIR/login_attempt_${PROTO}.html" \
      -w "HTTP %{http_code} | Redirect: %{redirect_url}\n" 2>/dev/null
  done
done

###############################################################################
# 6b. Unauthenticated endpoint access
###############################################################################
echo "[+] Testing for unauthenticated access to sensitive endpoints..."

SENSITIVE_PATHS=(
  "/properties/"
  "/general/status.dhtml"
  "/configurationPage"
  "/configReport"
  "/jobs/job_queue.dhtml"
  "/network/tcpip.dhtml"
  "/network/protocols.dhtml"
  "/security/audit.dhtml"
  "/security/certificates.dhtml"
  "/users/"
  "/users/roles"
  "/auditlog/"
  "/cloning/export"
  "/backup/"
  "/accounting/"
  "/ldap/"
  "/connectivity/"
  "/admin/config"
  "/debug/"
  "/diagnostics/"
  "/errorlog/"
  "/eventlog/"
  "/set_config"
  "/certs/"
  "/webservices/office/emailservice"
  "/api/v1/config"
  "/api/v1/network"
)

echo "Status | URL" > "$OUTDIR/unauth_access.txt"
echo "-------|----" >> "$OUTDIR/unauth_access.txt"

for SP in "${SENSITIVE_PATHS[@]}"; do
  for PROTO in http https; do
    CODE=$(curl -sk -o "$OUTDIR/unauth_$(echo ${PROTO}${SP} | tr '/:' '_').html" \
      -w "%{http_code}" --connect-timeout 3 "$PROTO://$TARGET$SP" 2>/dev/null)
    if [[ "$CODE" != "000" && "$CODE" != "404" ]]; then
      echo "  $CODE | $PROTO://$TARGET$SP" | tee -a "$OUTDIR/unauth_access.txt"

      # Flag anything returning 200 on a sensitive endpoint
      [[ "$CODE" == "200" ]] && echo "  [!!!] UNAUTH ACCESS: $PROTO://$TARGET$SP"
    fi
  done
done

###############################################################################
# 6c. HTTP method testing (PUT, DELETE, PATCH, OPTIONS)
###############################################################################
echo "[+] Testing HTTP methods on key endpoints..."

for EP in "/" "/properties/" "/admin/" "/set_config" "/api/v1/config"; do
  echo "  Endpoint: https://$TARGET$EP"
  for METHOD in OPTIONS PUT DELETE PATCH TRACE CONNECT; do
    CODE=$(curl -sk -X "$METHOD" -o /dev/null -w "%{http_code}" \
      --connect-timeout 3 "https://$TARGET$EP" 2>/dev/null)
    [[ "$CODE" != "000" && "$CODE" != "405" && "$CODE" != "404" ]] && \
      echo "    [!] $METHOD -> $CODE"
  done
done | tee "$OUTDIR/http_methods.txt"

###############################################################################
# 6d. Session/Cookie analysis
###############################################################################
echo "[+] Analyzing session management..."

# Check cookie attributes
curl -skIL --connect-timeout 5 "https://$TARGET/" 2>/dev/null \
  | grep -i 'set-cookie' | tee "$OUTDIR/cookies_analysis.txt"

# Check for session fixation
curl -skL -c "$OUTDIR/session_test1.txt" --connect-timeout 5 "https://$TARGET/" >/dev/null 2>&1
curl -skL -c "$OUTDIR/session_test2.txt" --connect-timeout 5 "https://$TARGET/" >/dev/null 2>&1

echo "[*] Auth testing complete. Review results in $OUTDIR/"
