#!/bin/sh

set -eu

conf="/vpn/vpn.conf"

remote_line=""
host=""
port=""
proto=""

if [ -f "$conf" ]; then
  remote_line=$(awk '/^remote /{print; exit}' "$conf" || true)
  proto=$(awk '/^proto /{print $2; exit}' "$conf" || true)
fi

if [ -n "$remote_line" ]; then
  set -- $remote_line
  hostpart="$2"
  if echo "$hostpart" | grep -q ':'; then
    host=$(echo "$hostpart" | cut -d: -f1)
    port=$(echo "$hostpart" | cut -d: -f2)
  else
    host="$hostpart"
    if [ "$#" -ge 3 ]; then port="$3"; fi
  fi
fi

: ${port:=1194}
: ${proto:=udp}

# Try direct connect to the VPN server port (TCP or UDP)
if [ -n "$host" ]; then
  if [ "$proto" = "tcp" ]; then
    nc -z -w 3 "$host" "$port" >/dev/null 2>&1 && exit 0
  else
    nc -z -u -w 3 "$host" "$port" >/dev/null 2>&1 && exit 0 || true
  fi
fi

# Fallback: if openvpn is running, test outbound connectivity through privoxy.
# Detect privoxy listen port from config (default 3128) and use it as proxy.
proxy_port=""
priv_conf="/etc/privoxy/privoxy.config"
if [ -f "$priv_conf" ]; then
  addr=$(awk '/^[[:space:]]*listen-address/ {print $2; exit}' "$priv_conf" || true)
  if [ -n "$addr" ]; then
    proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
  fi
fi
: ${proxy_port:=3128}

if pidof openvpn >/dev/null 2>&1; then
  curl -fsS --max-time 5 --proxy http://127.0.0.1:${proxy_port} http://example.com >/dev/null 2>&1 && exit 0
fi

exit 1
