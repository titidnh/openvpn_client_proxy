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
#   CAMOUFLAGE_FALLBACK      (true)  si aucun serveur ne repond en TLS sur
#                                     CAMOUFLAGE_PORT, demarre OpenVPN classique
#                                     (conf d origine) au lieu d echouer
#   CAMOUFLAGE_PROBE_MAX     (4)     nombre max d endpoints sondes
#
# PREREQUIS IMPORTANT : le serveur doit TERMINER le TLS sur CAMOUFLAGE_PORT
# (stunnel/sslh cote serveur, ou service "SSL/TLS OpenVPN" du fournisseur).
# Les serveurs OpenVPN/TCP standard (CyberGhost, fichiers .ovpn Surfshark...)
# parlent OpenVPN EN CLAIR sur 443 : ils ignorent un ClientHello TLS. Le
# "Camouflage" de l app Surfshark est une obfuscation XOR cote serveur, non
# disponible via les fichiers .ovpn manuels. Une sonde TLS (camouflage_probe_tls)
# detecte ce cas et declenche le repli.
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
    local sni_host="" host_count=0
    local entry host
    local connects=0

    for entry in ${VPN_REMOTE_MAP:-}; do
        host="${entry%%=*}"
        [ -n "$host" ] || continue
        [ -n "$sni_host" ] || sni_host="$host"
        host_count=$((host_count + 1))
    done

    {
        printf 'client = yes\n'
        printf 'foreground = no\n'
        printf 'pid = %s\n' "$CAMOUFLAGE_STUNNEL_PID"
        printf 'output = %s\n' "$CAMOUFLAGE_STUNNEL_LOG"
        printf '[openvpn-camouflage]\n'
        printf 'accept = 127.0.0.1:%s\n' "${CAMOUFLAGE_LOCAL_PORT:-1194}"
        local endpoint rest ip port proto
        for endpoint in $(camouflage_endpoints); do
            rest="${endpoint#*|}"
            ip="${endpoint%%|*}"
            port="${rest%%|*}"
            proto="${rest#*|}"
            [ -n "$ip" ] && [ -n "$port" ] || continue
            # Seuls les endpoints tcp/CAMOUFLAGE_PORT sont des cibles TLS
            # (le pare-feu epingle aussi le port d origine pour le repli).
            [ "$proto" = "tcp" ] && [ "$port" = "${CAMOUFLAGE_PORT:-443}" ] || continue
            printf 'connect = %s:%s\n' "$ip" "$port"
            connects=$((connects + 1))
        done
        if [ "${CAMOUFLAGE_TLS_VERIFY:-true}" != "false" ]; then
            # stunnel exige CAfile/CApath des que verify >= 2 ou verifyChain
            printf 'verifyChain = yes\n'
            printf 'CAfile = /etc/ssl/certs/ca-certificates.crt\n'
            if [ -n "$sni_host" ]; then
                printf 'sni = %s\n' "$sni_host"
                # Un seul hostname : verification du nom. Plusieurs : le
                # certificat ne peut pas correspondre a tous, chaine seule.
                [ "$host_count" -eq 1 ] && printf 'checkHost = %s\n' "$sni_host"
            fi
        else
            [ -n "$sni_host" ] && printf 'sni = %s\n' "$sni_host"
            printf 'verify = 0\n'
        fi
    } > "$out"

    if [ "$connects" -eq 0 ]; then
        log_json ERROR "camouflage" \
            "no VPN endpoint available for stunnel" \
            "hint=VPN_REMOTE_IPS has no tcp/${CAMOUFLAGE_PORT:-443} entry - check the firewall bootstrap logs"
        return 1
    fi
    chmod 600 "$out"
    return 0
}

# Endpoints cibles du mode camouflage : ceux retenus par la sonde TLS
# (CAMOUFLAGE_ENDPOINTS) sinon tous les endpoints epingles (VPN_REMOTE_IPS).
camouflage_endpoints() {
    printf '%s\n' "${CAMOUFLAGE_ENDPOINTS:-${VPN_REMOTE_IPS:-}}"
}

# Hostname (VPN_REMOTE_MAP "host=ip1,ip2 ...") auquel appartient une IP
# Usage: _camouflage_host_for_ip <ip>
_camouflage_host_for_ip() {
    local ip="$1" entry
    for entry in ${VPN_REMOTE_MAP:-}; do
        case ",${entry#*=}," in
            *",${ip},"*) printf '%s\n' "${entry%%=*}"; return 0 ;;
        esac
    done
    return 1
}

# Sonde : le serveur repond-il a un handshake TLS ? (time_appconnect > 0).
# Un serveur OpenVPN/TCP classique ignore le ClientHello -> echec/timeout.
# Verification volontairement desactivee ici (-k) : on teste seulement la
# presence d une terminaison TLS ; stunnel gere ensuite la verification.
# Usage: camouflage_probe_tls <ip> <port> [sni]
camouflage_probe_tls() {
    local ip="$1" port="$2" sni="${3:-}" t target
    command_exists curl || return 0   # pas de curl : on ne peut pas sonder
    if [ -n "$sni" ]; then
        target="https://${sni}:${port}/"
        t=$(curl -sk --noproxy '*' --connect-timeout 5 --max-time 8 \
            --resolve "${sni}:${port}:${ip}" -o /dev/null \
            -w '%{time_appconnect}' "$target" 2>/dev/null || true)
    else
        target="https://${ip}:${port}/"
        t=$(curl -sk --noproxy '*' --connect-timeout 5 --max-time 8 \
            -o /dev/null -w '%{time_appconnect}' "$target" 2>/dev/null || true)
    fi
    awk -v t="${t:-0}" 'BEGIN { exit !(t + 0 > 0) }'
}

# Sonde les endpoints tcp/CAMOUFLAGE_PORT et retient ceux qui parlent TLS
# dans CAMOUFLAGE_ENDPOINTS. Retour 1 si aucun ne repond en TLS.
# Usage: camouflage_select_endpoints
camouflage_select_endpoints() {
    local endpoint rest ip port proto host ok="" probed=0
    local max="${CAMOUFLAGE_PROBE_MAX:-4}"
    for endpoint in ${VPN_REMOTE_IPS:-}; do
        rest="${endpoint#*|}"
        ip="${endpoint%%|*}"
        port="${rest%%|*}"
        proto="${rest#*|}"
        [ "$proto" = "tcp" ] && [ "$port" = "${CAMOUFLAGE_PORT:-443}" ] || continue
        [ "$probed" -lt "$max" ] || break
        probed=$((probed + 1))
        host="$(_camouflage_host_for_ip "$ip" || true)"
        if camouflage_probe_tls "$ip" "$port" "$host"; then
            ok="$ok $endpoint"
            log_json INFO "camouflage" "TLS probe OK" "ip=${ip}" "port=${port}"
        else
            log_json WARN "camouflage" \
                "TLS probe FAILED - server does not terminate TLS on this port" \
                "ip=${ip}" "port=${port}"
        fi
    done
    export CAMOUFLAGE_ENDPOINTS="${ok# }"
    [ -n "$CAMOUFLAGE_ENDPOINTS" ]
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
        -v map="$(camouflage_endpoints)" '
        { sub(/^\xef\xbb\xbf/, ""); sub(/\r$/, "") }
        $1 == "proto" { next }
        $1 == "rport" { next }
        # Options reservees a UDP : OpenVPN refuse (ou ignore) en tcp-client
        $1 == "fast-io" { next }
        $1 == "fragment" { next }
        $1 == "explicit-exit-notify" { next }
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
                if (kv[1] != "" && !(kv[1] in seen)) {
                    seen[kv[1]] = 1
                    print "route " kv[1] " 255.255.255.255 net_gateway"
                }
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
