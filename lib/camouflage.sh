#!/bin/bash
# ===========================================================================
# lib/camouflage.sh - Mode Camouflage (obfuscation TLS du tunnel OpenVPN)
#
# Reproduit le comportement du mode "Camouflage" de l'application officielle
# Surfshark : le tunnel OpenVPN/TCP est encapsule dans une session TLS
# standard via stunnel, sur le port 443. Pour un observateur reseau (DPI,
# fournisseur d'acces, hotspot), le flux est indifferenciable du HTTPS.
#
# chaine : OpenVPN -> 127.0.0.1:CAMOUFLAGE_LOCAL_PORT -> stunnel (TLS)
#          -> <serveur VPN>:CAMOUFLAGE_PORT (tcp/443)
#
# Le fichier vpn.conf reste la configuration d'origine : les directives
# remote/proto et les blocs <connection> sont retires dans une copie
# temporaire (tmpfs), et OpenVPN se connecte a stunnel en local. Le pare-feu
# (lib/firewall.sh) epingle les IPs des serveurs VPN en tcp/CAMOUFLAGE_PORT.
#
# Variables :
#   ENABLE_CAMOUFLAGE        (false) active le mode camouflage (OpenVPN only)
#   CAMOUFLAGE_PORT          (443)   port TCP distant du serveur TLS
#   CAMOUFLAGE_LOCAL_PORT    (1194)  port local d'ecoute de stunnel
#   CAMOUFLAGE_TLS_VERIFY    (true)  verifie la chaine TLS du serveur
#                                     (verifyChain + checkHost + SNI)
# ===========================================================================

CAMOUFLAGE_STUNNEL_CONF="${CAMOUFLAGE_STUNNEL_CONF:-/run/stunnel-camouflage.conf}"
CAMOUFLAGE_STUNNEL_PID="${CAMOUFLAGE_STUNNEL_PID:-/run/stunnel-camouflage.pid}"
CAMOUFLAGE_STUNNEL_LOG="${CAMOUFLAGE_STUNNEL_LOG:-/tmp/stunnel-camouflage.log}"

# Le mode camouflage ne s'applique qu'a OpenVPN (pas WireGuard)
# Usage: camouflage_enabled
camouflage_enabled() {
    [ "${ENABLE_CAMOUFLAGE:-false}" = "true" ]
}

# Genere la configuration stunnel (client TLS) depuis les endpoints epingles
# par le pare-feu (VPN_REMOTE_IPS, forme "ip|port|proto"). Plusieurs
# directives connect = offrent du failover (round-robin stunnel).
# Le SNI/hostname est pris dans VPN_REMOTE_MAP (host=ip1,ip2 ...) quand
# disponible, sinon stunnel se connecte sans checkHost (l'authentification
# reste assuree par la couche TLS interne d'OpenVPN).
# Usage: generate_stunnel_conf <fichier_sortie>
generate_stunnel_conf() {
    local out="$1"
    local sni_host=""
    local entry host
    local connects=0

    for entry in ${VPN_REMOTE_MAP:-}; do
        host="${entry%%=*}"
        if [ -n "$host" ] && [ "${host#*=}" = "$host" ]; then
            sni_host="$host"
            break
        fi
    done

    {
        printf 'client = yes\n'
        printf 'foreground = no\n'
        printf 'pid = %s\n' "$CAMOUFLAGE_STUNNEL_PID"
        printf 'output = %s\n' "$CAMOUFLAGE_STUNNEL_LOG"
        printf '[openvpn-camouflage]\n'
        printf 'accept = 127.0.0.1:%s\n' "${CAMOUFLAGE_LOCAL_PORT:-1194}"
        local endpoint rest ip port
        for endpoint in ${VPN_REMOTE_IPS:-}; do
            rest="${endpoint#*|}"
            ip="${endpoint%%|*}"
            port="${rest%%|*}"
            [ -n "$ip" ] && [ -n "$port" ] || continue
            printf 'connect = %s:%s\n' "$ip" "$port"
            connects=$((connects + 1))
        done
        if [ -n "$sni_host" ]; then
            printf 'sni = %s\n' "$sni_host"
            if [ "${CAMOUFLAGE_TLS_VERIFY:-true}" != "false" ]; then
                printf 'verifyChain = yes\n'
                printf 'CAfile = /etc/ssl/certs/ca-certificates.crt\n'
                printf 'checkHost = %s\n' "$sni_host"
            else
                printf 'verify = 0\n'
            fi
        elif [ "${CAMOUFLAGE_TLS_VERIFY:-true}" != "false" ]; then
            printf 'verify = 2\n'
        fi
    } > "$out"

    if [ "$connects" -eq 0 ]; then
        log_json ERROR "camouflage" \
            "no VPN endpoint available for stunnel" \
            "hint=VPN_REMOTE_IPS is empty - check the firewall bootstrap logs"
        return 1
    fi
    chmod 600 "$out"
    return 0
}

# Genere la configuration OpenVPN camouflee : retire les directives
# remote/proto/rport et les blocs <connection>, ajoute la connexion locale
# vers stunnel et epingle les IPs serveur hors du tunnel (net_gateway) pour
# eviter que le trafic stunnel ne reboucle dans le tunnel lui-meme.
# Usage: build_camouflaged_openvpn_conf <config_source> <config_sortie>
build_camouflaged_openvpn_conf() {
    local src="$1" out="$2"
    [ -f "$src" ] || return 1
    umask 077
    awk \
        -v local_port="${CAMOUFLAGE_LOCAL_PORT:-1194}" \
        -v map="${VPN_REMOTE_IPS:-}" '
        { sub(/^\xef\xbb\xbf/, ""); sub(/\r$/, "") }
        $1 == "proto" { next }
        $1 == "rport" { next }
        $1 == "remote" { next }
        $1 == "<connection>" { inblock = 1; next }
        inblock && $1 == "</connection>" { inblock = 0; next }
        inblock { next }
        { print }
        END {
            print "proto tcp-client"
            print "remote 127.0.0.1 " local_port
            n = split(map, eps, " ")
            for (i = 1; i <= n; i++) {
                split(eps[i], kv, "|")
                if (kv[1] != "")
                    print "route " kv[1] " 255.255.255.255 net_gateway"
            }
        }
    ' "$src" > "$out" || return 1
    [ -s "$out" ] || return 1
    chmod 600 "$out"
    return 0
}

# Arrete l'instance stunnel du mode camouflage (si elle tourne)
# Usage: stop_stunnel
stop_stunnel() {
    local pid
    if [ -f "$CAMOUFLAGE_STUNNEL_PID" ]; then
        pid=$(cat "$CAMOUFLAGE_STUNNEL_PID" 2>/dev/null || true)
        if [ -n "${pid:-}" ] && [ "$pid" -gt 0 ] 2>/dev/null &&
            kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            local i
            for i in 1 2 3 4 5; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1
            done
            kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$CAMOUFLAGE_STUNNEL_PID"
    fi
    return 0
}

# Demarre stunnel en client TLS pour encapsuler OpenVPN
# Usage: start_stunnel
start_stunnel() {
    command_exists stunnel || {
        log_json ERROR "camouflage" "stunnel binary not found"
        return 1
    }
    stop_stunnel
    mkdir -p "$(dirname "$CAMOUFLAGE_STUNNEL_CONF")" \
        "$(dirname "$CAMOUFLAGE_STUNNEL_PID")" 2>/dev/null || true
    generate_stunnel_conf "$CAMOUFLAGE_STUNNEL_CONF" || return 1
    stunnel "$CAMOUFLAGE_STUNNEL_CONF" || {
        log_json ERROR "camouflage" \
            "stunnel failed to start" \
            "conf=${CAMOUFLAGE_STUNNEL_CONF}"
        return 1
    }
    local i
    for i in 1 2 3 4 5; do
        [ -f "$CAMOUFLAGE_STUNNEL_PID" ] && break
        sleep 1
    done
    if [ ! -f "$CAMOUFLAGE_STUNNEL_PID" ]; then
        log_json ERROR "camouflage" \
            "stunnel did not write its pid file" \
            "expected=${CAMOUFLAGE_STUNNEL_PID}"
        return 1
    fi
    log_json INFO "camouflage" \
        "stunnel started - OpenVPN wrapped in TLS" \
        "pid=$(cat "$CAMOUFLAGE_STUNNEL_PID" 2>/dev/null || echo unknown)" \
        "listen=127.0.0.1:${CAMOUFLAGE_LOCAL_PORT:-1194}" \
        "remote_port=${CAMOUFLAGE_PORT:-443}"
    return 0
}
