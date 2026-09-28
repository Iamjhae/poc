#!/bin/bash
# Phase 1: Full Port Scan & Service Enumeration
# Target: Xerox Printer 13.13.1.112
# NOTE: Port 9100 PJL/PS access is OUT OF SCOPE (known issue)

TARGET="13.13.1.112"
OUTDIR="../results/01_portscan"
mkdir -p "$OUTDIR"

echo "[*] Phase 1: Port Scanning - $TARGET"
echo "[*] Output: $OUTDIR"
echo ""

# Full TCP SYN scan - all 65535 ports
echo "[+] Running full TCP SYN scan..."
nmap -sS -p- -T4 --min-rate=1000 -oA "$OUTDIR/tcp_full" "$TARGET"

# Top UDP ports (printers use SNMP/161, mDNS/5353, LPD/515, etc.)
echo "[+] Running UDP scan on common printer ports..."
nmap -sU -p 53,67,68,69,80,123,161,162,443,515,631,1900,3702,5353,5357,8080,9100,9200 \
  -oA "$OUTDIR/udp_common" "$TARGET"

# Aggressive service/version detection on all open TCP ports
echo "[+] Running service version detection..."
nmap -sV -sC -O --version-intensity 9 -p- -oA "$OUTDIR/tcp_versions" "$TARGET"

# Xerox-specific port checks
echo "[+] Scanning Xerox-specific ports..."
nmap -sS -sV -p 80,443,515,631,9100,9200,10080,49152-49300 \
  --script=banner,http-title,http-server-header,ssl-cert \
  -oA "$OUTDIR/xerox_specific" "$TARGET"

echo "[*] Port scan complete. Review results in $OUTDIR/"
