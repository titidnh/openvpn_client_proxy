#!/bin/sh

set -e

dir="/vpn"
conf="$dir/vpn.conf"
exec openvpn --cd "$dir" --config "$conf"