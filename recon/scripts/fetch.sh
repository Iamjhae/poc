#!/bin/bash
# Fetch HTTPS page from 13.13.1.110 via openssl s_client
TARGET="13.13.1.110"
PROXY="127.0.0.1:34153"
PATH_REQ="${1:-/}"

(echo -e "GET $PATH_REQ HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; sleep 2) | \
  timeout 10 openssl s_client -connect "$TARGET:443" -proxy "$PROXY" -tls1_2 -quiet 2>/dev/null
