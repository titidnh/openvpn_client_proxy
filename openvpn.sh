#!/bin/sh

set -e
set -o pipefail

dir="/vpn"
conf="$dir/vpn.conf"
exec openvpn --cd "$dir" --config "$conf"