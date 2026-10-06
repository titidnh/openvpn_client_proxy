#!/bin/bash

# ===========================================================================
# start.sh - thin orchestrator
# ===========================================================================

source "/usr/local/lib/common.sh"
source "/usr/local/lib/firewall.sh"
source "/usr/local/lib/dns_runtime.sh"
source "/usr/local/lib/dns_blocklist.sh"
source "/usr/local/lib/dot.sh"
source "/usr/local/lib/wireguard.sh"
source "/usr/local/lib/supervisor.sh"

# ===========================================================================
# Prometheus metrics
# ===========================================================================

update_metrics() {
    local vpn_up="${METRIC_VPN_UP:-0}"
    local restart_count="${METRIC_RESTART_COUNT:-0}"
    local dot_active="${METRIC_DOT_ACTIVE:-0}"
    local start_ts="${METRIC_START_TS:-$(date +%s)}"
    local last_restart_ts="${METRIC_LAST_RESTART_TS:-0}"

    printf '%s\n' "$vpn_up" \
        > "${METRICS_DIR}/metric_vpn_up" 2>/dev/null || true

    printf '%s\n' "$restart_count" \
        > "${METRICS_DIR}/metric_restart_count" 2>/dev/null || true

    printf '%s\n' "$dot_active" \
        > "${METRICS_DIR}/metric_dot_active" 2>/dev/null || true

    printf '%s\n' "$start_ts" \
        > "${METRICS_DIR}/metric_start_ts" 2>/dev/null || true

    printf '%s\n' "$last_restart_ts" \
        > "${METRICS_DIR}/metric_last_restart_ts" 2>/dev/null || true
}

start_metrics() {
    [ "${ENABLE_METRICS:-false}" = "true" ] || return 0

    if ! command_exists nc; then
        log_json WARN "start_metrics" \
            "nc not available - metrics disabled"
        return 0
    fi

    mkdir -p "$METRICS_DIR"

    # R4 : heredoc CITE - le contenu ne doit pas etre evalue a la generation.
    # METRICS_DIR est injecte via printf, pas par interpolation du shell.
    {
        printf '#!/bin/sh\nMETRICS_DIR=%s\n' "$(printf "%q" "${METRICS_DIR}")"
        cat <<'HANDLER'

vpn_up=$(cat "$METRICS_DIR/metric_vpn_up" 2>/dev/null || echo 0)
restart_total=$(cat "$METRICS_DIR/metric_restart_count" 2>/dev/null || echo 0)
dot_active=$(cat "$METRICS_DIR/metric_dot_active" 2>/dev/null || echo 0)
start_ts=$(cat "$METRICS_DIR/metric_start_ts" 2>/dev/null || echo 0)
last_restart=$(cat "$METRICS_DIR/metric_last_restart_ts" 2>/dev/null || echo 0)

now=$(date +%s)
uptime_s=$((now - start_ts))

body="# HELP vpn_up VPN tunnel status (1=up 0=down)
# TYPE vpn_up gauge
vpn_up ${vpn_up}
# HELP vpn_restart_total Total supervisor restart cycles
# TYPE vpn_restart_total counter
vpn_restart_total ${restart_total}
# HELP dot_active DNS-over-TLS active
# TYPE dot_active gauge
dot_active ${dot_active}
# HELP process_uptime_seconds Container uptime in seconds
# TYPE process_uptime_seconds gauge
process_uptime_seconds ${uptime_s}
# HELP last_restart_timestamp_seconds Epoch of last supervisor restart
# TYPE last_restart_timestamp_seconds gauge
last_restart_timestamp_seconds ${last_restart}
"

len=${#body}

printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
    "$len" "$body"
HANDLER
    } > /tmp/metrics_handler.sh

    chmod +x /tmp/metrics_handler.sh

    update_metrics

    if command_exists socat; then
        socat \
            TCP-LISTEN:9100,bind=127.0.0.1,reuseaddr,fork \
            EXEC:/tmp/metrics_handler.sh &

        SERVICE_PIDS["metrics"]=$!
    else
        (
            while true; do
                nc -l 127.0.0.1 9100 \
                    < <(/tmp/metrics_handler.sh) \
                    2>/dev/null || sleep 1
            done
        ) &

        SERVICE_PIDS["metrics"]=$!

        log_json WARN "start_metrics" \
            "socat not found, using nc fallback (one request at a time)"
    fi

    log_json INFO "start_metrics" \
        "metrics endpoint started" \
        "pid=${SERVICE_PIDS["metrics"]}" \
        "addr=127.0.0.1:9100"
}

# ===========================================================================
# Capabilities
# ===========================================================================

# S4 : l'ancienne implementation appelait prctl(PR_CAPBSET_DROP) dans un
# processus python3 ENFANT : seul ce processus perdait ses capabilities,
# puis se terminait. Superviseur et demons gardaient tout - la fonction
# n'a jamais rien fait. La reduction des capabilities se fait desormais au
# niveau du conteneur (cap_drop / cap_add dans docker-compose, voir README).
drop_capabilities() {
    [ "${DROP_CAPS:-false}" = "true" ] || return 0

    log_json WARN "drop_caps" \
        "DROP_CAPS is deprecated and has no effect - use cap_drop/cap_add in docker-compose (see README)"
}

# ===========================================================================
# Proxy
# ===========================================================================

configure_privoxy_auth() {
    log_json INFO "configure_privoxy_auth" \
        "Configuring Privoxy authentication"

    local user="${PROXY_USER:-}"
    local pass="${PROXY_PASS:-}"
    local privoxy_port
    local privoxy_addr

    if [ -n "$user" ] && [ -n "$pass" ]; then
        privoxy_port=$((PROXY_PORT + 1))
        privoxy_addr="127.0.0.1"

        sed -i \
            "s|^listen-address .*|listen-address ${privoxy_addr}:${privoxy_port}|" \
            "$PRIVOXY_CONF"

        log_json INFO "configure_privoxy_auth" \
            "auth enabled - privoxy on ${privoxy_addr}:${privoxy_port}"
    else
        privoxy_port="$PROXY_PORT"
        privoxy_addr="0.0.0.0"

        sed -i \
            "s|^listen-address .*|listen-address ${privoxy_addr}:${privoxy_port}|" \
            "$PRIVOXY_CONF"

        log_json INFO "configure_privoxy_auth" \
            "no auth - privoxy on ${privoxy_addr}:${privoxy_port}"
    fi

    # S3 : sed -i recree le fichier -> il redevient root:root. Privoxy lance
    # avec --user refuse une config possedee par root (check_file_rights).
    # Restaurer le proprietaire attendu par le demon.
    chown "${PROXY_RUN_USER:-vpn}":"${PROXY_RUN_USER:-vpn}" "$PRIVOXY_CONF" 2>/dev/null || true
    chmod 640 "$PRIVOXY_CONF" 2>/dev/null || true
    log_json DEBUG "configure_privoxy_auth" \
        "privoxy config ownership" \
        "file=${PRIVOXY_CONF}" "owner=$(stat -c '%U:%G' "$PRIVOXY_CONF" 2>/dev/null || echo '?')" \
        "mode=$(stat -c '%a' "$PRIVOXY_CONF" 2>/dev/null || echo '?')"
}

start_privoxy() {
    log_json INFO "start_privoxy" \
        "Starting Privoxy"

    configure_privoxy_auth

    # S3/S7 : Privoxy analyse du contenu web non fiable - ne pas le laisser
    # en root. Il abandonne ses privileges apres le bind du port. L'UID sert
    # aussi au filtre iptables PROXY_EGRESS (setup_proxy_egress_filter).
    /usr/sbin/privoxy \
        --no-daemon \
        --user "${PROXY_RUN_USER:-vpn}" \
        "$PRIVOXY_CONF" &

    SERVICE_PIDS["privoxy"]=$!

    # H4 : verifier que le demon a vraiment demarre (config invalide =
    # processus qui meurt aussitot). Retour non nul pour le fail-closed.
    sleep_wait 1
    if ! is_process_running "${SERVICE_PIDS["privoxy"]}"; then
        log_json ERROR "start_privoxy" "privoxy died immediately (invalid config?)"
        return 1
    fi
}

start_nginx_auth() {
    # C5 : nginx est un reverse proxy - il ne gere ni CONNECT ni le code 407.
    # Les clients proxy envoient "Proxy-Authorization" et attendent "407",
    # jamais "Authorization"/"401". On utilise tinyproxy (BasicAuth natif,
    # CONNECT natif, reponses 407 correctes) comme frontal authentifiant
    # devant Privoxy. Le nom de fonction est conserve pour compatibilite.
    log_json INFO "start_nginx_auth" \
        "Starting authenticated proxy frontend (tinyproxy)"

    local user="${PROXY_USER:-}"
    local pass="${PROXY_PASS:-}"

    [ -n "$user" ] && [ -n "$pass" ] || return 0

    if ! command_exists tinyproxy; then
        # Fail-closed : sans frontal authentifiant, le proxy ne doit PAS
        # rester muet (Privoxy n'ecoute que sur 127.0.0.1:PORT+1) ni exposer
        # un port non protege. On arrete le superviseur avec une erreur.
        log_json ERROR "start_nginx_auth" \
            "tinyproxy not found - cannot start authenticated proxy" \
            "hint=install tinyproxy in the image"
        return 1
    fi

    # B2 : tinyproxy BasicAuth n'accepte quasiment que [A-Za-z0-9._-]
    # (testé 1.11.1 : s3cr3t! p@ss a$b x:y a%b a&b a+b a=b a/b a,b a;b
    # a'b a"b a(b) a?b a~b é -> "Syntax error", le demon refuse de partir).
    # Valider le jeu exact et echouer explicitement plutot que de laisser
    # le demon mourir en boucle.
    if ! [[ "$user" =~ ^[A-Za-z0-9._-]{1,64}$ ]] ||
       ! [[ "$pass" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
        log_json ERROR "start_nginx_auth" \
            "PROXY_USER/PROXY_PASS must only contain [A-Za-z0-9._-] (tinyproxy BasicAuth limit)" \
            "hint=change the password or use a different auth frontend (squid/3proxy)"
        return 1
    fi

    local privoxy_internal_port=$((PROXY_PORT + 1))

    # Attendre que Privoxy (backend interne) ecoute
    local i
    for i in 1 2 3 4 5; do
        if nc -z -w 1 127.0.0.1 "$privoxy_internal_port" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    mkdir -p /var/log/tinyproxy /run/tinyproxy

    local tiny_conf=/etc/tinyproxy/tinyproxy_auth.conf
    mkdir -p /etc/tinyproxy

    # umask 077 : la config contient le mot de passe en clair.
    umask 077
    cat > "$tiny_conf" <<TINYCONF
Port ${PROXY_PORT}
Listen 0.0.0.0
Timeout 600
PidFile "/run/tinyproxy/tinyproxy_auth.pid"
MaxClients 100
DisableViaHeader Yes
LogLevel Critical
BasicAuth ${user} ${pass}
Upstream http 127.0.0.1:${privoxy_internal_port}
TINYCONF
    umask 022

    # NB : pas de directive "Allow" - en tinyproxy une seule directive Allow
    # suffit a refuser TOUTE adresse non listee (les clients Docker non
    # loopback auraient eu 403 meme avec de bons identifiants). Le filtrage
    # reseau est fait par iptables (ALLOW_EXTERNAL_PROXY_ACCESS).
    # -d : foreground, sinon tinyproxy demonise et $! serait le PID du
    # parent deja sorti (R1a).
    tinyproxy -d -c "$tiny_conf" &
    SERVICE_PIDS["nginx"]=$!

    # B2 : sonde de vie - tinyproxy meurt aussitot sur une config refusee
    # (BasicAuth invalide, port pris). Sans cette sonde, le superviseur
    # bouclerait sur "auth proxy died".
    sleep_wait 1
    if ! is_process_running "${SERVICE_PIDS["nginx"]}"; then
        log_json ERROR "start_nginx_auth" \
            "tinyproxy died immediately (invalid config or port in use)"
        return 1
    fi

    log_json INFO "start_nginx_auth" \
        "started" \
        "pid=${SERVICE_PIDS["nginx"]}" \
        "frontend=0.0.0.0:${PROXY_PORT} (tinyproxy, BasicAuth)" \
        "backend=127.0.0.1:${privoxy_internal_port}"
}
# ===========================================================================
# VPN
# ===========================================================================

start_vpn_service() {
    case "$VPN_TYPE_SELECTED" in
        openvpn)
            start_openvpn_local
            ;;
        wireguard)
            start_wireguard_local
            ;;
        *)
            log_json ERROR "start_vpn_service" \
                "Unknown VPN type" \
                "type=${VPN_TYPE_SELECTED}"
            return 1
            ;;
    esac
}

start_openvpn_local() {
    log_json INFO "start_openvpn" \
        "Starting OpenVPN"

    /usr/local/bin/openvpn.sh &

    SERVICE_PIDS["vpn"]=$!
}

start_wireguard_local() {
    if start_wireguard; then
        # Le tunnel wg0 n'a pas de processus demon : le superviseur doit
        # verifier l'interface (find_vpn_interface) et le handshake
        # (wireguard_handshake_ok), pas un PID (C4-2). Un processus sentinelle
        # est tout de meme garde pour la compat SERVICE_PIDS.
        sleep infinity &
        SERVICE_PIDS["vpn"]=$!
        log_json INFO "start_wireguard" "sentinel pid=${SERVICE_PIDS[vpn]} (supervision via interface/handshake)"
    else
        SERVICE_PIDS["vpn"]=0
        return 1
    fi
}

check_vpn_routing() {
    command_exists ip || return 0
    if ! vpn_tunnel_ready; then
        return 1
    fi
    # WireGuard : l'interface peut exister sans handshake actif - sans
    # handshake le tunnel ne route rien (C4-2).
    if [ "${VPN_TYPE_SELECTED:-openvpn}" = "wireguard" ]; then
        wireguard_handshake_ok || return 1
    fi
    return 0
}

restart_vpn_service() {
    log_json WARN "supervisor" \
        "restarting VPN (${VPN_TYPE_SELECTED})" \
        "pid=${SERVICE_PIDS["vpn"]:-unknown}"

    kill_if_running "${SERVICE_PIDS["vpn"]}"

    if [ -n "${SERVICE_PIDS["vpn"]}" ]; then
        wait "${SERVICE_PIDS["vpn"]}" 2>/dev/null || true
    fi

    SERVICE_PIDS["vpn"]=0

    cleanup_routes_on_restart
    start_vpn_service

    # Une reconnexion OpenVPN (TLS, pull de config, montage tun) prend
    # facilement 5-15 s ; avec 5 s le superviseur declarait un echec alors
    # que la reconnexion etait en cours et relancait toute la pile pour
    # rien. Meme fenetre que wait_for_vpn_tunnel au demarrage.
    local i

    for i in $(seq 1 30); do
        sleep 1

        if check_vpn_routing; then
            log_json INFO "supervisor" \
                "VPN routing restored" \
                "pid=${SERVICE_PIDS["vpn"]}"

            return 0
        fi
    done

    log_json ERROR "supervisor" \
        "VPN routing still not functional after restart (${VPN_TYPE_SELECTED})"

    return 1
}

# ===========================================================================
# Healthcheck
# ===========================================================================

run_service_healthcheck() {
    local log_file="/tmp/healthcheck.log"
    local healthcheck_in_progress="/tmp/healthcheck_in_progress"
    local max_retries=3
    local retry=0
    local success=0

    # Mark that healthcheck is in progress to prevent supervisor from removing sentinel
    touch "$healthcheck_in_progress"

    while [ "$retry" -lt "$max_retries" ]; do
        if /usr/local/bin/healthcheck.sh \
            >"$log_file" 2>&1; then

            success=1
            break
        fi

        retry=$((retry + 1))

        log_json WARN "supervisor" \
            "healthcheck failed (attempt ${retry}/${max_retries}) - retrying in 5s"

        sleep 5
    done

    # Clear the flag that healthcheck is in progress
    rm -f "$healthcheck_in_progress"

    if [ "$success" -eq 0 ]; then
        cat "$log_file" >&2 || true

        log_json WARN "supervisor" \
            "healthcheck failed after ${max_retries} retries - restarting services"

        rm -f "$VPN_HEALTHY_FILE"

        METRIC_VPN_UP=0

        return 1
    fi

    return 0
}

# IP publique reelle du reseau physique, memorisee en phase 0 (tunnel absent).
# Reference anti-fuite : si l'IP publique via le tunnel egale cette IP, le
# tunnel ne route rien (C6).
capture_real_ip() {
    # Optionnelle (§4-5) : la requete revele l'IP reelle a un tiers a chaque
    # demarrage - desactivee par defaut. Sans reference, la detection de
    # fuite IP (public == IP reelle) est desactivee (loggue WARN).
    if [ "${COLLECT_REAL_IP:-false}" != "true" ]; then
        # 3.6 : sortir muet rend la desactivation invisible - INFO unique
        log_json INFO "capture_real_ip" \
            "leak detection disabled - COLLECT_REAL_IP=false"
        REAL_IP=""
        return 0
    fi

    if ! command_exists curl; then
        REAL_IP=""
        return 0
    fi

    # Endpoint SANS DNS (le lockdown a vide le NAT Docker 127.0.0.11, la
    # resolution de api.ipify.org echouerait). 1.1.1.1 repond en direct.
    REAL_IP=$(
        timeout 10 curl -fsS --max-time 8 "https://1.1.1.1/cdn-cgi/trace" 2>/dev/null |
            awk -F= '$1=="ip"{print $2}' || true
    )

    if [ -n "$REAL_IP" ]; then
        log_json INFO "capture_real_ip" \
            "host public IP memorized (leak reference)" \
            "ip=${REAL_IP}"
    else
        # Sans reference, la detection de fuite (public IP == IP reelle) est
        # silencieusement desactivee : il faut le signaler, pas l'ignorer.
        log_json WARN "capture_real_ip" \
            "could not capture host public IP - leak detection disabled"
    fi
}

check_vpn_ip() {
    log_json INFO "check_vpn_ip" \
        "Checking VPN public IP"

    if ! command_exists curl; then
        log_json WARN "check_vpn_ip" \
            "curl not available - cannot verify tunnel egress"
        return 1
    fi

    local proxy_port
    proxy_port=$(get_privoxy_port)

    if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
        log_json WARN "check_vpn_ip" \
            "privoxy not listening on ${proxy_port} - tunnel egress unverifiable"
        return 1
    fi

    local public_ip
    # Le port interne Privoxy ne demande PAS d'auth : inutile (et dangereux,
    # cf M6) d'y incorporer PROXY_USER/PROXY_PASS.
    local proxy_url="http://127.0.0.1:${proxy_port}"

    public_ip=$(
        curl \
            -fsS \
            --max-time 20 \
            --retry 3 \
            --retry-delay 2 \
            --proxy "$proxy_url" \
            "https://api.ipify.org" \
            2>/dev/null || true
    )

    if [ -z "$public_ip" ]; then
        log_json ERROR "check_vpn_ip" \
            "no public IP via proxy - tunnel not operational"
        return 1
    fi

    if [ -n "${REAL_IP:-}" ] && [ "$public_ip" = "$REAL_IP" ]; then
        log_json ERROR "check_vpn_ip" \
            "LEAK DETECTED: public IP via tunnel equals host IP" \
            "public_ip=${public_ip}" "real_ip=${REAL_IP}"
        return 1
    fi

    log_json INFO "check_vpn_ip" \
        "public IP via VPN confirmed" \
        "ip=${public_ip}"

    METRIC_VPN_UP=1
    return 0
}

# ===========================================================================
# Tailscale
# ===========================================================================

tailscale_has_state() {
    [ -s /var/lib/tailscale/tailscaled.state ]
}

tailscale_can_advertise_exit_node() {
    local ipv4_forward
    local ipv6_forward

    ipv4_forward=$(
        cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0
    )

    ipv6_forward=$(
        cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0
    )

    [ "$ipv4_forward" = "1" ] &&
        [ "$ipv6_forward" = "1" ]
}

build_tailscale_up_flags() {
    local up_flags="${TAILSCALE_FLAGS:-}"

    if [ "${TAILSCALE_ACCEPT_ROUTES:-false}" = "true" ]; then
        up_flags="$up_flags --accept-routes"
    fi

    if [ -n "${TAILSCALE_HOSTNAME:-}" ]; then
        up_flags="$up_flags --hostname=${TAILSCALE_HOSTNAME}"
    fi

    if [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ]; then
        if tailscale_can_advertise_exit_node; then
            up_flags="$up_flags --advertise-exit-node"
        else
            log_json WARN "start_tailscale" \
                "exit-node advertisement requested but forwarding sysctls are disabled" \
                "required=net.ipv4.ip_forward=1,net.ipv6.conf.all.forwarding=1"
        fi
    fi

    printf '%s\n' "$up_flags"
}

run_tailscale_up_async() {
    local up_flags="$1"

    log_json INFO "start_tailscale" \
        "running 'tailscale up'"

    (
        # shellcheck disable=SC2086
        ts_cli up \
            --accept-dns=false \
            $up_flags \
            > /var/log/tailscale-up.log 2>&1
    ) &
}

start_tailscale() {
    log_json INFO "start_tailscale" \
        "Starting Tailscale"

    [ "${ENABLE_TAILSCALE:-false}" = "true" ] || return 0

    # v12 : idempotent - le keepalive peut appeler start_tailscale en
    # differe ; ne jamais lancer un deuxieme tailscaled.
    if [ "${SERVICE_PIDS[tailscaled]:-0}" -ne 0 ] && \
       is_process_running "${SERVICE_PIDS[tailscaled]}"; then
        log_json DEBUG "start_tailscale" \
            "tailscaled already running - skipping"
        return 0
    fi

    if ! command_exists tailscaled; then
        log_json WARN "start_tailscale" \
            "tailscaled not installed - skipping"
        return 0
    fi

    mkdir -p \
        /var/lib/tailscale \
        "$TAILSCALE_RUN_DIR" || true

    log_json INFO "start_tailscale" \
        "starting tailscaled"

    tailscaled \
        --state="/var/lib/tailscale/tailscaled.state" \
        --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" \
        >/var/log/tailscaled.log 2>&1 &

    export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
    SERVICE_PIDS["tailscaled"]=$!

    # M8 : le CLI tailscale ne lit PAS TAILSCALE_SOCKET (variable
    # containerboot) ; il faut --socket a chaque invocation, sinon le CLI
    # cherche /var/run/tailscale/tailscaled.sock et ne joint pas le demon.
    ts_cli() { tailscale --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" "$@"; }

    local waited=0

    until ts_cli status >/dev/null 2>&1 ||
        [ "$waited" -ge 20 ]; do

        sleep_wait 1
        waited=$((waited + 1))
    done

    if ! ts_cli status >/dev/null 2>&1; then
        log_json WARN "start_tailscale" \
            "tailscale daemon socket not ready after wait window"
    fi

    local up_flags
    up_flags=$(build_tailscale_up_flags)

    if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
        # M6 : le CLI tailscale ne lit PAS TS_AUTHKEY (variable containerboot,
        # confirmé par cmd/tailscale/cli/up.go). Seuls --auth-key=<cle> ou
        # --auth-key=file:/chemin existent. On ecrit la cle dans un fichier
        # 0600 (jamais sur la ligne de commande, visible dans ps) et on passe
        # file: au CLI.
        local authkey_file=/run/tailscale_authkey
        umask 077
        printf '%s' "$TAILSCALE_AUTHKEY" > "$authkey_file"
        umask 022
        (
            # shellcheck disable=SC2086
            ts_cli up --accept-dns=false --auth-key="file:${authkey_file}" $up_flags \
                > /var/log/tailscale-up.log 2>&1
            rm -f "$authkey_file"
        ) &
        return 0
    fi

    if tailscale_has_state; then
        log_json INFO "start_tailscale" \
            "existing tailscale state detected - refreshing settings without authkey"

        run_tailscale_up_async "$up_flags"

        return 0
    fi

    log_json WARN "start_tailscale" \
        "no authkey and no persisted state - skipping 'tailscale up'"
}

# ===========================================================================
# Signals
# ===========================================================================

declare -g _CLEANUP_RUNNING=0

cleanup() {
    if [ "$_CLEANUP_RUNNING" -eq 0 ]; then
        log_json INFO "cleanup" \
            "Cleaning up services"
        _CLEANUP_RUNNING=1
    fi

    rm -f "$VPN_HEALTHY_FILE"

    local service

    for service in "${!SERVICE_PIDS[@]}"; do
        kill_if_running "${SERVICE_PIDS[$service]}"
    done

    local all_pids=""

    local pid
    for pid in "${SERVICE_PIDS[@]}"; do
        if [ -n "$pid" ] && [ "$pid" -ne 0 ]; then
            all_pids="$all_pids $pid"
        fi
    done

    if [ -n "$all_pids" ]; then
        # shellcheck disable=SC2086
        wait $all_pids 2>/dev/null || true
    fi

    log_json INFO "cleanup" \
        "All services stopped"

    _CLEANUP_RUNNING=0

    exit 0
}

trap cleanup INT TERM

# ===========================================================================
# Entry point
# ===========================================================================

init_environment

log_json INFO "start.sh" \
    "Starting openvpn_client_proxy" \
    "version=2.1.0"

mkdir -p "$METRICS_DIR"

supervise_all
