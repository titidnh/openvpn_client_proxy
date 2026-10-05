#!/bin/bash

# ===========================================================================
# openvpn.sh - Script de lancement d'OpenVPN
# 
# Ce script lance OpenVPN avec la configuration spécifiée.
# Il est conçu pour être appelé par le superviseur principal (start.sh).
# 
# Auteur: Vibe Code (amélioration 2026)
# Licence: MIT
# Version: 2.0.0
# ===========================================================================

set -euo pipefail

# Charger les fonctions communes
source "/usr/local/lib/common.sh"

# Initialiser l'environnement
init_environment

# ===========================================================================
# Configuration
# ===========================================================================

# Dossier et fichier de configuration OpenVPN
dir="${DEFAULT_VPN_DIR}"
conf="${dir}/vpn.conf"

# Vérifier que le fichier de configuration existe
if [ ! -f "$conf" ]; then
    log_json ERROR "openvpn.sh" \
        "Configuration file not found" \
        "expected=${conf}"
    exit 1
fi

# Vérifier que le dossier existe
if [ ! -d "$dir" ]; then
    log_json ERROR "openvpn.sh" \
        "Configuration directory not found" \
        "expected=${dir}"
    exit 1
fi

# Vérifier que OpenVPN est installé
if ! command_exists openvpn; then
    log_json ERROR "openvpn.sh" "openvpn command not found"
    exit 1
fi

# ===========================================================================
# Exécution
# ===========================================================================

# v8 : si le pare-feu a resolu les remotes (VPN_REMOTE_MAP, "host=ip1,ip2 ..."),
# ecrire une config OU les lignes remote host sont remplacees par les IPs
# resolues - OpenVPN ne doit PAS re-resoudre le hostname, sinon il peut
# obtenir une autre IP du round-robin DNS, bloquee par le kill switch.
if [ -n "${VPN_REMOTE_MAP:-}" ]; then
    resolved_conf="$dir/vpn.resolved.conf"
    awk -v map="${VPN_REMOTE_MAP}" '
        BEGIN {
            n = split(map, m, " ")
            for (i = 1; i <= n; i++) {
                split(m[i], kv, "=")
                hosts[kv[1]] = kv[2]
            }
        }
        {
            if ($1 == "remote" && ($2 in hosts)) {
                sub(/\r$/, "")
                port = ($3 ~ /^[0-9]+$/) ? $3 : ""
                proto = ($4 != "") ? $4 : ""
                np = split(hosts[$2], ips, ",")
                for (j = 1; j <= np; j++) {
                    line = "remote " ips[j]
                    if (port != "") line = line " " port
                    if (proto != "") line = line " " proto
                    print line
                }
                next
            }
            print
        }
    ' "$conf" > "$resolved_conf"
    if [ -s "$resolved_conf" ]; then
        chmod 600 "$resolved_conf"
        log_json INFO "openvpn.sh" \
            "using firewall-resolved remotes config" \
            "map=${VPN_REMOTE_MAP}"
        conf="$resolved_conf"
    else
        log_json WARN "openvpn.sh" "resolved config generation failed - using original"
    fi
fi

log_json INFO "openvpn.sh" \
    "Starting OpenVPN" \
    "config=${conf}" \
    "dir=${dir}"

exec openvpn --cd "$dir" --config "$conf"
