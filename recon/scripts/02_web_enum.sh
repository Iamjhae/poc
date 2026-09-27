#!/bin/bash
# Phase 2: Web Interface Enumeration
# Xerox printers expose Embedded Web Server (EWS) on 80/443
# Also check alternate ports: 8080, 10080, etc.

TARGET="13.13.1.112"
OUTDIR="../results/02_web_enum"
mkdir -p "$OUTDIR"

echo "[*] Phase 2: Web Interface Enumeration - $TARGET"

###############################################################################
# 2a. Grab headers, certificates, and baseline responses
###############################################################################
echo "[+] Grabbing HTTP/HTTPS headers and certificates..."

for PORT in 80 443 8080 10080; do
  PROTO="http"
  [[ "$PORT" == "443" ]] && PROTO="https"

  echo "  -> $PROTO://$TARGET:$PORT"
  curl -skIL --connect-timeout 5 "$PROTO://$TARGET:$PORT/" \
    -o "$OUTDIR/headers_${PORT}.txt" 2>/dev/null

  # Full response with body
  curl -skL --connect-timeout 5 "$PROTO://$TARGET:$PORT/" \
    -o "$OUTDIR/homepage_${PORT}.html" 2>/dev/null
done

# TLS certificate details (hostname disclosure is known/OOS but grab for context)
echo "[+] Extracting TLS certificate info..."
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
  | openssl x509 -noout -text > "$OUTDIR/tls_cert.txt" 2>/dev/null

###############################################################################
# 2b. Directory brute-force with Xerox-specific wordlist
###############################################################################
echo "[+] Running directory enumeration..."

WORDLIST="../wordlists/xerox_paths.txt"

# Using gobuster if available, fallback to ffuf or manual curl
if command -v gobuster &>/dev/null; then
  for PROTO in http https; do
    gobuster dir -u "$PROTO://$TARGET" -w "$WORDLIST" \
      -k -t 20 -s "200,201,301,302,403" \
      -o "$OUTDIR/gobuster_${PROTO}.txt" 2>/dev/null
  done
elif command -v ffuf &>/dev/null; then
  for PROTO in http https; do
    ffuf -u "$PROTO://$TARGET/FUZZ" -w "$WORDLIST" \
      -mc 200,201,301,302,403 -k -t 20 \
      -o "$OUTDIR/ffuf_${PROTO}.json" 2>/dev/null
  done
else
  echo "[!] No gobuster/ffuf found. Running manual curl checks..."
  while IFS= read -r path; do
    path="${path#/}"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 "https://$TARGET/$path")
    [[ "$CODE" != "000" && "$CODE" != "404" ]] && echo "$CODE https://$TARGET/$path"
  done < "$WORDLIST" | tee "$OUTDIR/manual_enum.txt"
fi

###############################################################################
# 2c. Nmap HTTP scripts
###############################################################################
echo "[+] Running Nmap HTTP enumeration scripts..."
nmap -p 80,443 --script=http-enum,http-methods,http-robots.txt,http-config-backup,http-default-accounts \
  -oA "$OUTDIR/nmap_http" "$TARGET"

echo "[*] Web enumeration complete. Review results in $OUTDIR/"
