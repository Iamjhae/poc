#!/bin/bash
# Phase 5: Firmware & Model Identification + Vulnerability Mapping
# The scope encourages firmware analysis: "You can access the firmware from support.xerox.com"

TARGET="13.13.1.112"
OUTDIR="../results/05_firmware"
mkdir -p "$OUTDIR"

echo "[*] Phase 5: Firmware & Model Identification - $TARGET"

###############################################################################
# 5a. Extract model and firmware version from web UI
###############################################################################
echo "[+] Extracting model and firmware info from web interface..."

# Common Xerox endpoints that leak model/firmware
ENDPOINTS=(
  "/"
  "/home.html"
  "/properties/"
  "/general/status.dhtml"
  "/configurationPage"
  "/configReport"
  "/getDeviceInfo"
  "/DeviceDescription"
  "/status"
  "/devicestatus"
  "/getConfiguration"
  "/FirmwareVersion"
  "/webservices/general/status"
  "/PRESENTATION/LOGIN"
  "/PRESENTATION/MASTERPAGE"
  "/api/v1/status"
  "/api/v1/system"
)

for EP in "${ENDPOINTS[@]}"; do
  RESP=$(curl -skL --connect-timeout 5 "https://$TARGET$EP" 2>/dev/null)
  if [[ -n "$RESP" && "$RESP" != *"404"* ]]; then
    echo "$RESP" > "$OUTDIR/endpoint_$(echo $EP | tr '/' '_').html"

    # Extract model patterns
    MODEL=$(echo "$RESP" | grep -ioP '(VersaLink|AltaLink|WorkCentre|Phaser|ColorQube|B\d{3,4}|C\d{3,4})[^\s<"]*' | head -5)
    FW=$(echo "$RESP" | grep -ioP '(firmware|version|fw)[:\s]*[0-9]+\.[0-9]+[^\s<"]*' | head -5)

    [[ -n "$MODEL" ]] && echo "  [!] Model hints from $EP: $MODEL"
    [[ -n "$FW" ]] && echo "  [!] Firmware hints from $EP: $FW"
  fi
done 2>/dev/null | tee "$OUTDIR/model_firmware_info.txt"

###############################################################################
# 5b. Extract from SNMP
###############################################################################
echo "[+] Extracting model/firmware from SNMP..."

COMM="public"
[[ -f "../results/03_snmp/valid_communities.txt" ]] && COMM=$(head -1 "../results/03_snmp/valid_communities.txt")

# sysDescr often contains model and firmware
snmpget -v2c -c "$COMM" -OvQ "$TARGET" 1.3.6.1.2.1.1.1.0 2>/dev/null | tee -a "$OUTDIR/snmp_model.txt"

# Printer MIB - prtGeneralPrinterName
snmpget -v2c -c "$COMM" -OvQ "$TARGET" 1.3.6.1.2.1.43.5.1.1.16.1 2>/dev/null | tee -a "$OUTDIR/snmp_model.txt"

# Serial number
snmpget -v2c -c "$COMM" -OvQ "$TARGET" 1.3.6.1.2.1.43.5.1.1.17.1 2>/dev/null | tee -a "$OUTDIR/snmp_model.txt"

# Installed firmware versions via Host Resources MIB
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.25.6.3.1.2 2>/dev/null | tee -a "$OUTDIR/snmp_installed_sw.txt"

###############################################################################
# 5c. Check Xerox Security Bulletins
###############################################################################
echo "[+] Generating Xerox security bulletin lookup URLs..."

cat > "$OUTDIR/xerox_security_references.txt" <<'EOF'
Xerox Security Bulletins & Firmware:

1. Security Bulletins:
   https://security.business.xerox.com/
   https://securitydocs.business.xerox.com/

2. Firmware Downloads:
   https://www.support.xerox.com/
   Search by model number identified above

3. Known CVEs for Xerox printers (search NVD):
   https://nvd.nist.gov/vuln/search/results?query=xerox

4. Key CVE Families to research for identified model:
   - CVE-2024-* Xerox (recent vulns)
   - CVE-2023-* Xerox
   - OpenSSL vulns in embedded firmware
   - CUPS vulnerabilities
   - Net-SNMP vulnerabilities
   - Linux kernel vulns (many Xerox printers run embedded Linux)

5. Exploit databases:
   - https://www.exploit-db.com/search?q=xerox
   - Metasploit: search xerox / printer modules

6. Useful tools for firmware analysis:
   - binwalk: firmware extraction
   - firmwalker: firmware filesystem analysis
   - EMBA: embedded firmware analyzer
   - jefferson: JFFS2 extraction
   - sasquatch: SquashFS extraction
EOF

echo "[*] Firmware identification complete. Review results in $OUTDIR/"
echo "[*] Download firmware from support.xerox.com for the identified model"
echo "[*] Then run: binwalk -e <firmware_file> to extract and analyze"
