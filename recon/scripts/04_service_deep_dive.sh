#!/bin/bash
# Phase 4: Deep Service Enumeration
# Covers IPP, LPD, mDNS/DNS-SD, WSD, UPnP, FTP, Telnet, SSH, SOAP

TARGET="13.13.1.112"
OUTDIR="../results/04_services"
mkdir -p "$OUTDIR"

echo "[*] Phase 4: Deep Service Enumeration - $TARGET"

###############################################################################
# 4a. IPP (Internet Printing Protocol) - port 631 / 443
###############################################################################
echo "[+] IPP enumeration..."

# Get printer attributes via IPP
ipptool -tv "ipp://$TARGET/ipp/print" get-printer-attributes.test \
  > "$OUTDIR/ipp_attributes.txt" 2>/dev/null

# Try alternate IPP paths
for IPP_PATH in /ipp /ipp/print /IPP /IPP/print /printers; do
  curl -sk --connect-timeout 3 -X POST \
    -H "Content-Type: application/ipp" \
    "http://$TARGET:631$IPP_PATH" \
    -o "$OUTDIR/ipp_probe_$(echo $IPP_PATH | tr '/' '_').bin" 2>/dev/null
done

# Nmap IPP scripts
nmap -p 631 --script=ipp-info -oA "$OUTDIR/nmap_ipp" "$TARGET" 2>/dev/null

###############################################################################
# 4b. LPD (Line Printer Daemon) - port 515
###############################################################################
echo "[+] LPD enumeration..."
nmap -p 515 --script=lpd-info -oA "$OUTDIR/nmap_lpd" "$TARGET" 2>/dev/null

###############################################################################
# 4c. mDNS / DNS-SD / Bonjour - port 5353
###############################################################################
echo "[+] mDNS/DNS-SD service discovery..."

# Query for printer services
if command -v avahi-browse &>/dev/null; then
  timeout 10 avahi-browse -art 2>/dev/null | grep -i "$TARGET" > "$OUTDIR/avahi_browse.txt"
fi

# Direct mDNS query
if command -v dig &>/dev/null; then
  dig @"$TARGET" -p 5353 _printer._tcp.local PTR +short > "$OUTDIR/mdns_printer.txt" 2>/dev/null
  dig @"$TARGET" -p 5353 _ipp._tcp.local PTR +short >> "$OUTDIR/mdns_printer.txt" 2>/dev/null
  dig @"$TARGET" -p 5353 _ipps._tcp.local PTR +short >> "$OUTDIR/mdns_printer.txt" 2>/dev/null
  dig @"$TARGET" -p 5353 _pdl-datastream._tcp.local PTR +short >> "$OUTDIR/mdns_printer.txt" 2>/dev/null
  dig @"$TARGET" -p 5353 _http._tcp.local PTR +short >> "$OUTDIR/mdns_printer.txt" 2>/dev/null
fi

###############################################################################
# 4d. WS-Discovery / WSD - port 3702 / 5357
###############################################################################
echo "[+] WS-Discovery probe..."
# Send WS-Discovery probe
cat <<'SOAP' | curl -sk -X POST -H "Content-Type: application/soap+xml" \
  -d @- "http://$TARGET:3702" -o "$OUTDIR/wsd_probe.xml" 2>/dev/null
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:recon-probe-001</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  </soap:Header>
  <soap:Body>
    <wsd:Probe/>
  </soap:Body>
</soap:Envelope>
SOAP

###############################################################################
# 4e. UPnP / SSDP - port 1900
###############################################################################
echo "[+] UPnP/SSDP discovery..."
# M-SEARCH for all devices
echo -e "M-SEARCH * HTTP/1.1\r\nHOST: $TARGET:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n" \
  | timeout 5 nc -u "$TARGET" 1900 > "$OUTDIR/ssdp_response.txt" 2>/dev/null

# Fetch UPnP description if available
curl -sk --connect-timeout 3 "http://$TARGET:1900/upnp/description.xml" \
  -o "$OUTDIR/upnp_description.xml" 2>/dev/null
curl -sk --connect-timeout 3 "http://$TARGET/description.xml" \
  -o "$OUTDIR/upnp_description2.xml" 2>/dev/null

###############################################################################
# 4f. FTP - port 21
###############################################################################
echo "[+] FTP enumeration..."
nmap -p 21 --script=ftp-anon,ftp-syst,ftp-bounce -oA "$OUTDIR/nmap_ftp" "$TARGET" 2>/dev/null

# Try anonymous FTP
curl -s --connect-timeout 5 "ftp://$TARGET/" --user "anonymous:anonymous" \
  --list-only > "$OUTDIR/ftp_listing.txt" 2>/dev/null

###############################################################################
# 4g. Telnet - port 23
###############################################################################
echo "[+] Telnet banner grab..."
echo "" | timeout 5 nc "$TARGET" 23 > "$OUTDIR/telnet_banner.txt" 2>/dev/null

nmap -p 23 --script=telnet-ntlm-info -oA "$OUTDIR/nmap_telnet" "$TARGET" 2>/dev/null

###############################################################################
# 4h. SSH - port 22
###############################################################################
echo "[+] SSH enumeration..."
nmap -p 22 --script=ssh2-enum-algos,ssh-auth-methods -oA "$OUTDIR/nmap_ssh" "$TARGET" 2>/dev/null
ssh-keyscan "$TARGET" > "$OUTDIR/ssh_hostkeys.txt" 2>/dev/null

###############################################################################
# 4i. SOAP/XML Web Services
###############################################################################
echo "[+] Probing SOAP/XML endpoints..."

SOAP_PATHS=("/webservices" "/services" "/soap" "/wsdl" "/SSMIService"
            "/webservices/office/emailservice" "/webservices/general/status")

for SP in "${SOAP_PATHS[@]}"; do
  CODE=$(curl -sk -o "$OUTDIR/soap_$(echo $SP | tr '/' '_').xml" \
    -w "%{http_code}" --connect-timeout 3 "https://$TARGET$SP" 2>/dev/null)
  [[ "$CODE" != "000" && "$CODE" != "404" ]] && echo "  [!] $CODE -> https://$TARGET$SP"
done

echo "[*] Service enumeration complete. Review results in $OUTDIR/"
