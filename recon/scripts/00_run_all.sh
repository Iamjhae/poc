#!/bin/bash
# Master Recon Runner for Xerox Printer 13.13.1.112
# Xerox Bug Bounty (HackerOne Private Program)
#
# PREREQUISITES:
#   - Connected to program VPN/network with access to 13.13.1.x subnet
#   - Tools: nmap, curl, openssl, snmpwalk/snmpget, nc
#   - Optional: gobuster/ffuf, testssl.sh, ipptool, PRET, avahi-browse
#
# OUT OF SCOPE REMINDERS (13.13.1.112):
#   - Medium: Unauthenticated PJL and PS Access on Raw Print Port 9100
#   - Medium: Unauthenticated Information Disclosure via eSCL ScannerCapabilities
#   - Low: Internal Hostname Disclosure via TLS Certificate
#   - Physical attacks, DoS, brute force, automated scanner findings
#
# USAGE: ./00_run_all.sh [phase_number]
#   No args = run all phases sequentially
#   With arg = run specific phase only (e.g., ./00_run_all.sh 3)

set -e

TARGET="13.13.1.112"
RESULTS_DIR="../results"
mkdir -p "$RESULTS_DIR"

echo "============================================"
echo "  Xerox Printer Deep Recon: $TARGET"
echo "  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================"

# Connectivity check
echo "[*] Checking target connectivity..."
if ! timeout 5 bash -c "echo >/dev/tcp/$TARGET/80" 2>/dev/null && \
   ! timeout 5 bash -c "echo >/dev/tcp/$TARGET/443" 2>/dev/null; then
  echo "[!] Cannot reach $TARGET on port 80 or 443."
  echo "[!] Ensure you are connected to the program network/VPN."
  exit 1
fi
echo "[+] Target is reachable."

PHASE="${1:-all}"

run_phase() {
  local num=$1 script=$2 desc=$3
  echo ""
  echo "=========================================="
  echo "  Phase $num: $desc"
  echo "=========================================="
  bash "$script" 2>&1 | tee "$RESULTS_DIR/phase_${num}.log"
}

if [[ "$PHASE" == "all" || "$PHASE" == "1" ]]; then
  run_phase 1 "01_port_scan.sh" "Port Scanning & Service Detection"
fi

if [[ "$PHASE" == "all" || "$PHASE" == "2" ]]; then
  run_phase 2 "02_web_enum.sh" "Web Interface Enumeration"
fi

if [[ "$PHASE" == "all" || "$PHASE" == "3" ]]; then
  run_phase 3 "03_snmp_enum.sh" "SNMP Enumeration"
fi

if [[ "$PHASE" == "all" || "$PHASE" == "4" ]]; then
  run_phase 4 "04_service_deep_dive.sh" "Deep Service Enumeration"
fi

if [[ "$PHASE" == "all" || "$PHASE" == "5" ]]; then
  run_phase 5 "05_firmware_analysis.sh" "Firmware & Model Identification"
fi

if [[ "$PHASE" == "all" || "$PHASE" == "6" ]]; then
  run_phase 6 "06_auth_bypass.sh" "Authentication Testing"
fi

if [[ "$PHASE" == "all" || "$PHASE" == "7" ]]; then
  run_phase 7 "07_vuln_scan.sh" "Vulnerability Assessment"
fi

if [[ "$PHASE" == "all" || "$PHASE" == "8" ]]; then
  run_phase 8 "08_lateral_movement_recon.sh" "Lateral Movement Recon"
fi

if [[ "$PHASE" == "all" || "$PHASE" == "9" ]]; then
  run_phase 9 "09_print_protocol_attacks.sh" "Print Protocol Exploitation"
fi

echo ""
echo "============================================"
echo "  Recon Complete!"
echo "  Results saved to: $RESULTS_DIR/"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Review results in each phase directory"
echo "  2. Download firmware from support.xerox.com for identified model"
echo "  3. Run 'binwalk -e <firmware>' for deep firmware analysis"
echo "  4. Cross-reference findings with Xerox security bulletins"
echo "  5. Document and submit findings via HackerOne"
