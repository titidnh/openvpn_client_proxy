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
    # /vpn est souvent monte en lecture seule (volume ro) - la config
    # resolue est ecrite dans un tmpfs (memoire), JAMAIS dans /tmp :
    # docker-compose.yml monte un volume nomme persistant sur /tmp, et la
    # config copiee embarque les secrets inline (<key>, <auth-user-pass>).
    # umask 077 : le fichier est cree en 600 (pas de fenetre en 644).
    # --cd reste sur $dir pour les certificats/cles relatifs de la config
    # d origine.
    umask 077
    resolved_conf="$(mktemp /dev/shm/vpn.resolved.XXXXXX 2>/dev/null \
        || mktemp /run/vpn.resolved.XXXXXX 2>/dev/null \
        || mktemp /tmp/vpn.resolved.XXXXXX)"
    awk -v map="${VPN_REMOTE_MAP}" '
        BEGIN {
            n = split(map, m, " ")
            for (i = 1; i <= n; i++) {
                split(m[i], kv, "=")
                hosts[kv[1]] = kv[2]
            }
        }
        # v8-3.2 : meme nettoyage que parse_vpn_remotes (BOM UTF-8, CR) -
        # sinon un remote en 1re ligne avec BOM n est pas reecrit et
        # OpenVPN re-resout le hostname (IP non autorisee, kill switch).
        { sub(/^\xef\xbb\xbf/, ""); sub(/\r$/, "") }
        {
            if ($1 == "remote" && ($2 in hosts)) {
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
            if ($1 == "remote" && $2 !~ /^[0-9.]+$/ && ($2 in hosts) == 0)
                left = $2
            print
        }
        END {
            if (left)
                print "WARN: remote hostname non epingle par VPN_REMOTE_MAP: " left > "/dev/stderr"
        }
    ' "$conf" > "$resolved_conf" || true
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
