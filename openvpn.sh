#!/usr/bin/env bash

set -x

dir="/vpn"
conf="$dir/vpn.conf"
exec openvpn --cd "$dir" --config "$conf"