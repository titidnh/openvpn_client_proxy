#!/bin/bash
# Supervisor orchestration extracted from start.sh

# Attente interruptible : le trap INT/TERM s'execute pendant le sleep
# au lieu d'attendre la fin de la commande (H9).
sleep_wait() {
    sleep "$1" &
    wait $! 2>/dev/null || true
}

# B3 : arret propre de la pile. Les "continue" du superviseur doivent
# nettoyer les services deja lances, sinon un echec transitoire laisse des
# processus orphelins (privoxy ne peut plus se binder a l'iteration
# suivante -> blocage permanent jusqu'au redemarrage du conteneur).
stop_stack() {
    local s
    for s in vpn nginx privoxy unbound dnsmasq; do
        kill_if_running "${SERVICE_PIDS[$s]:-0}"
        SERVICE_PIDS[$s]=0
    done
    pkill -x privoxy 2>/dev/null
    pkill -x tinyproxy 2>/dev/null
    return 0
}

# Drapeaux d'etat pour les taches de fond : ne pas dependre du compteur
# d'essais, sinon un echec DNS a l'iteration 1 empeche metrics/refresh de
# demarrer pour toute la vie du conteneur (C7).
_BG_METRICS_STARTED=0
_BG_DOT_REFRESH_STARTED=0
_BG_BLOCKLIST_REFRESH_STARTED=0

supervise_all() {
    log_json INFO "supervisor" \
        "Starting supervisor" \
        "version=2.2.0"

    local attempt=0
    local FW_FAIL_MAX=5
    local FW_FAIL_COUNT=0

    validate_environment || true

    # Kill switch des la premiere seconde (H5) : sans cela le conteneur
    # tourne en ACCEPT par defaut pendant les phases blocklist/dnsmasq/unbound.
    # §4-6 : sans kill switch, le conteneur fuirait - arret explicite plutot
    # qu'un demarrage en ACCEPT par defaut silencieux.
    if ! firewall_early_lockdown; then
        log_json ERROR "supervisor" \
            "early lockdown failed - aborting (no kill switch possible)"
        return 1
    fi

    # Memorise l'IP publique reelle (reference anti-fuite pour check_vpn_ip)
    capture_real_ip

    cp "$RESOLV_CONF" /tmp/resolv.conf.bak 2>/dev/null || true

    echo "nameserver ${DNS_SERVER_1}" > "$RESOLV_CONF"
    echo "nameserver ${DNS_SERVER_2}" >> "$RESOLV_CONF"

    while true; do
        attempt=$((attempt + 1))

        # Counter Prometheus monotone : ne redescend jamais (M1).
        # L'iteration initiale (attempt=1) n'est PAS un redemarrage.
        if [ "$attempt" -gt 1 ]; then
            METRIC_RESTART_COUNT=$((METRIC_RESTART_COUNT + 1))
            METRIC_LAST_RESTART_TS=$(date +%s)
            # S1 : le kill switch final n'autorise le DNS que via le tunnel,
            # or ce cycle relance dnsmasq/unbound AVANT le VPN. Le proxy est
            # arrete a ce stade : re-ouvrir le DNS de bootstrap est sans fuite.
            firewall_open_bootstrap_dns
        fi

        # Phase 0 : Blocklist DNS
        if [ "${ENABLE_DNS_BLOCKLIST:-false}" = "true" ]; then
            if download_blocklists; then
                compile_blocklists || true
            fi
        fi

        # Phase 1 : DNS classique
        start_dnsmasq_classic

        if ! wait_for_dns_ready 30; then
            log_json WARN "supervisor" "classic dns not ready - continuing"
        else
            sleep_wait 2
        fi

        # Phase 1.5 : Pre-load DoT IPs
        if [ "${ENABLE_DOT:-false}" = "true" ]; then
            preload_dot_ips
        fi

        # Phase 2 : Unbound / DoT
        start_unbound

        if [ "${ENABLE_DOT:-false}" = "true" ] && [ -s "$DOT_FORWARD_ADDRS_FILE" ]; then
            log_json INFO "supervisor" "DoT configured - waiting for stabilization..."
            sleep_wait 3
        fi

        # Verification DNS readiness
        if [ "${ENABLE_DOT:-false}" = "true" ]; then
            log_json INFO "supervisor" "waiting for DNS services to be ready..."

            local dns_ready=0
            local i

            for i in $(seq 1 90); do
                if nc -z -w 2 127.0.0.1 5053 >/dev/null 2>&1; then
                    if test_unbound_dns_robust; then
                        dns_ready=1
                        log_json INFO "supervisor" "DoT DNS ready" "wait_cycles=${i}"
                        break
                    fi
                elif [ $((i % 10)) -eq 0 ]; then
                    log_json DEBUG "supervisor" "DoT DNS still initializing" "cycles=${i}"
                fi

                sleep_wait 2
            done

            if [ "$dns_ready" -ne 1 ]; then
                log_json ERROR "supervisor" "DNS services (unbound/dnsmasq) not ready - retrying"
                kill_if_running "${SERVICE_PIDS[dnsmasq]}"
                kill_if_running "${SERVICE_PIDS[unbound]}"

                SERVICE_PIDS[dnsmasq]=0
                SERVICE_PIDS[unbound]=0

                sleep_wait 5
                continue
            fi
        else
            local dns_ready=0
            local i

            for i in $(seq 1 15); do
                if nslookup example.com 127.0.0.1 >/dev/null 2>&1 || \
                   dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
                    dns_ready=1
                    break
                fi

                sleep_wait 1
            done

            if [ "$dns_ready" -ne 1 ]; then
                log_json ERROR "supervisor" "dnsmasq not ready after 15s - retrying"
                kill_if_running "${SERVICE_PIDS[dnsmasq]}"
                SERVICE_PIDS[dnsmasq]=0

                sleep_wait 5
                continue
            fi
        fi

        # Firewall and services
        # H4 : plus de set -e - chaque retour critique est verifie.
        # Si le kill switch ne peut pas etre pose, on NE demarre PAS les
        # services (fail-closed) : un proxy sans kill switch fuirait.
        if ! setup_iptables; then
            # 3.2 : VPN_REMOTE_IPS est calculee une seule fois au bootstrap.
            # Si le DNS etait indisponible au boot, reessayer dans la boucle
            # ne re-resoudra rien (liste vide figee) -> boucle infinie. Apres
            # FW_FAIL_MAX echecs consecutifs, on sort : la politique de
            # redemarrage Docker relancera un bootstrap complet (qui
            # re-resoudra les remotes).
            FW_FAIL_COUNT=$((FW_FAIL_COUNT + 1))
            log_json ERROR "supervisor" \
                "setup_iptables failed - refusing to start services (fail-closed)" \
                "consecutive_failures=${FW_FAIL_COUNT}/${FW_FAIL_MAX}"
            if [ "$FW_FAIL_COUNT" -ge "$FW_FAIL_MAX" ]; then
                log_json ERROR "supervisor" \
                    "giving up after ${FW_FAIL_COUNT} consecutive firewall failures - exiting for full re-bootstrap"
                stop_stack
                return 1
            fi
            stop_stack
            sleep_wait 30
            continue
        fi
        # S5 : l'echec IPv6 est aussi bloquant (fail-closed).
        if ! setup_ip6tables; then
            FW_FAIL_COUNT=$((FW_FAIL_COUNT + 1))
            log_json ERROR "supervisor" \
                "setup_ip6tables failed - refusing to start services (fail-closed)" \
                "consecutive_failures=${FW_FAIL_COUNT}/${FW_FAIL_MAX}"
            stop_stack
            if [ "$FW_FAIL_COUNT" -ge "$FW_FAIL_MAX" ]; then
                return 1
            fi
            sleep_wait 30
            continue
        fi
        FW_FAIL_COUNT=0
        setup_proxy_routing

        if ! start_privoxy; then
            log_json ERROR "supervisor" "privoxy failed to start"
            stop_stack
            sleep_wait 10
            continue
        fi
        if ! start_nginx_auth; then
            log_json ERROR "supervisor" "auth proxy failed to start"
            stop_stack
            sleep_wait 10
            continue
        fi
        if ! start_vpn_service; then
            log_json ERROR "supervisor" "VPN service failed to start"
            stop_stack
            sleep_wait 10
            continue
        fi

        if [ "$_BG_METRICS_STARTED" -eq 0 ]; then
            start_metrics
            _BG_METRICS_STARTED=1
        fi
        if [ "$_BG_DOT_REFRESH_STARTED" -eq 0 ]; then
            start_dot_ip_refresh
            _BG_DOT_REFRESH_STARTED=1
        fi
        if [ "$_BG_BLOCKLIST_REFRESH_STARTED" -eq 0 ]; then
            start_blocklist_refresh
            _BG_BLOCKLIST_REFRESH_STARTED=1
        fi

        log_json INFO "supervisor" "waiting for VPN tunnel..."

        local tun_ready=0
        if wait_for_vpn_tunnel 30; then
            tun_ready=1
        fi

        if [ "$tun_ready" -eq 1 ]; then
            setup_return_routes
            check_vpn_ip || true

            log_json INFO "supervisor" "waiting for tunnel to be fully operational..."

            local full_ready=0
            # v12 : en mode DoT, unbound doit retablir ses connexions TLS
            # (853) via le tunnel avant que curl ne resolve api.ipify.org -
            # la fenetre de 15 s etait trop courte (Tailscale etait
            # definitivement saute alors que le tunnel devenait sain ~40 s
            # plus tard, cf keepalive "tunnel health confirmed").
            local full_tries=3
            [ "${ENABLE_DOT:-false}" = "true" ] && full_tries=9
            for i in $(seq 1 "$full_tries"); do
                if check_vpn_ip && nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                    full_ready=1
                    break
                fi
                sleep_wait 5
            done

            if [ "$full_ready" -eq 1 ]; then
                touch "$VPN_HEALTHY_FILE"
                METRIC_VPN_UP=1
                start_tailscale
            else
                log_json WARN "supervisor" \
                    "tunnel not fully operational yet - Tailscale deferred to keepalive loop"
                rm -f "$VPN_HEALTHY_FILE"
                METRIC_VPN_UP=0
            fi
        else
            log_json WARN "supervisor" "tunnel not ready after 30s - skipping return routes"
            rm -f "$VPN_HEALTHY_FILE"
            METRIC_VPN_UP=0
        fi

        if [ "$attempt" -eq 1 ]; then
            drop_capabilities
        fi

        update_metrics

        log_json INFO "supervisor" "all services running" "vpn=${SERVICE_PIDS[vpn]}" "dnsmasq=${SERVICE_PIDS[dnsmasq]:-unknown}" "privoxy=${SERVICE_PIDS[privoxy]:-unknown}" "nginx_auth=${SERVICE_PIDS[nginx]:-disabled}" "unbound=${SERVICE_PIDS[unbound]:-disabled}" "metrics=${SERVICE_PIDS[metrics]:-disabled}" "dot_refresh=${SERVICE_PIDS[dot_refresh]:-disabled}" "blocklist_refresh=${SERVICE_PIDS[blocklist_refresh]:-disabled}"

        log_json INFO "supervisor" "waiting 40s before first healthcheck for stability..."
        sleep_wait 40

        local fail=0
        local start_time
        start_time=$(date +%s)
        local stable_cycles=0

        log_json INFO "supervisor" "entering keepalive loop - sentinel vpn_healthy will be maintained" "interval=10s"

        local keepalive_cycles=0
        # v12 : Tailscale differe - lance des que le tunnel est reellement
        # sain si la fenetre de demarrage l a saute (DoT : unbound doit
        # retablir ses connexions 853 via le tunnel). start_tailscale est
        # idempotent (garde sur SERVICE_PIDS/tailscaled).
        local tailscale_pending=0
        if [ "${ENABLE_TAILSCALE:-false}" = "true" ] && \
           [ "${SERVICE_PIDS[tailscaled]:-0}" -eq 0 ]; then
            tailscale_pending=1
        fi
        while true; do
            sleep_wait 10
            keepalive_cycles=$((keepalive_cycles + 1))
            fail=0

            local current_time
            local elapsed_minutes
            current_time=$(date +%s)
            elapsed_minutes=$(( (current_time - start_time) / 60 ))

            # Dette "IP figees" (v10) : re-resolution periodique des remotes
            # VPN. refresh_vpn_remote_ips met deja le pare-feu et la carte
            # VPN_REMOTE_MAP a jour sans couper le tunnel en cours (regles
            # posees AVANT retrait, connexion etablie preservee par conntrack
            # ESTABLISHED,RELATED). Un tunnel SAIN n est DONC PAS redemarre
            # ici : les nouvelles IP sont epinglees par openvpn.sh au prochain
            # (re)demarrage du VPN - spontane (deconnexion fournisseur) ou
            # pilote par l echec detecte par les sondes ci-dessous
            # (check_vpn_routing / healthcheck), la relance utilisant alors
            # la carte fraiche. Redemarrer au moindre changement d IP cassait
            # un tunnel stable pour rien (rotation DNS horaire du fournisseur).
            local refresh_interval="${VPN_REMOTE_REFRESH_INTERVAL:-3600}"
            if [ "$refresh_interval" != "0" ] && \
               [ "$((refresh_interval / 10))" -gt 0 ] && \
               [ $((keepalive_cycles % (refresh_interval / 10) )) -eq 0 ]; then
                if ! refresh_vpn_remote_ips; then
                    log_json INFO "supervisor" \
                        "VPN remote IPs changed - firewall updated, new IPs will be pinned on next VPN (re)start"
                fi
            fi

            if ! check_vpn_routing; then
                log_json WARN "supervisor" "VPN tunnel is down"
                rm -f "$VPN_HEALTHY_FILE"
                METRIC_VPN_UP=0

                if restart_vpn_service; then
                    setup_return_routes
                    if check_vpn_ip && nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                        touch "$VPN_HEALTHY_FILE"
                        METRIC_VPN_UP=1
                        log_json INFO "supervisor" "VPN tunnel recovered without full service restart"
                        update_metrics
                        continue
                    fi
                fi

                fail=1
            fi

            if [ "$fail" -eq 0 ]; then
                local dns_ok=0
                if [ "${ENABLE_DOT:-false}" = "true" ]; then
                    if nc -z -w 2 127.0.0.1 5053 >/dev/null 2>&1 && test_unbound_dns_robust && nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                        dns_ok=1
                    fi
                else
                    if nslookup example.com 127.0.0.1 >/dev/null 2>&1 || dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
                        dns_ok=1
                    fi
                fi

                if [ "$dns_ok" -eq 1 ]; then
                    touch "$VPN_HEALTHY_FILE"
                    METRIC_VPN_UP=1
                    if [ "$tailscale_pending" -eq 1 ] && \
                       check_vpn_ip && start_tailscale; then
                        tailscale_pending=0
                        log_json INFO "supervisor" \
                            "tunnel now fully operational - Tailscale started"
                    fi
                    if [ $((keepalive_cycles % 6)) -eq 0 ]; then
                        log_json DEBUG "supervisor" "tunnel health confirmed" "cycles=${keepalive_cycles}" "vpn_healthy=true"
                    fi
                else
                    # Don't remove sentinel if healthcheck is in progress (prevents race condition)
                    if [ ! -f /tmp/healthcheck_in_progress ]; then
                        rm -f "$VPN_HEALTHY_FILE"
                        log_json WARN "supervisor" "local DNS health check failed"
                    else
                        log_json WARN "supervisor" "local DNS health check failed but healthcheck in progress - keeping sentinel"
                    fi
                    METRIC_VPN_UP=0
                    fail=1
                fi
            fi

            if [ "$fail" -eq 0 ] && [ "$elapsed_minutes" -ge "$SKIP_HEALTHCHECK_FIRST_MINUTES" ]; then
                if ! run_service_healthcheck; then
                    fail=1
                fi
            elif [ "$elapsed_minutes" -lt "$SKIP_HEALTHCHECK_FIRST_MINUTES" ]; then
                log_json INFO "supervisor" "skipping healthcheck" "elapsed=${elapsed_minutes}min" "required=${SKIP_HEALTHCHECK_FIRST_MINUTES}min"
            fi

            if [ "$fail" -eq 0 ] && ! is_process_running "${SERVICE_PIDS[vpn]}"; then
                log_json ERROR "supervisor" "openvpn process died"
                fail=1
            fi

            if [ "$fail" -eq 0 ]; then
                local proxy_port
                proxy_port=$(get_privoxy_port)
                if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
                    log_json ERROR "supervisor" "privoxy not listening" "port=${proxy_port}"
                    fail=1
                fi
            fi

            if [ "$fail" -eq 0 ] && [ "${SERVICE_PIDS[nginx]}" -ne 0 ]; then
                if ! is_process_running "${SERVICE_PIDS[nginx]}"; then
                    log_json ERROR "supervisor" "nginx auth proxy died"
                    fail=1
                elif ! nc -z -w 3 127.0.0.1 "${PROXY_PORT:-3128}" >/dev/null 2>&1; then
                    log_json ERROR "supervisor" "nginx auth proxy not listening"
                    fail=1
                fi
            fi

            if [ "$fail" -eq 0 ] && [ "${ENABLE_DOT:-false}" = "true" ]; then
                if ! is_process_running "${SERVICE_PIDS[unbound]}"; then
                    log_json ERROR "supervisor" "unbound process died"
                    METRIC_DOT_ACTIVE=0
                    fail=1
                elif ! nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
                    log_json ERROR "supervisor" "unbound not listening on 5053"
                    METRIC_DOT_ACTIVE=0
                    fail=1
                fi
            fi

            if [ "$fail" -eq 0 ]; then
                # C8 : le refresh blocklist (sous-shell) peut relancer dnsmasq
                # sans mettre a jour SERVICE_PIDS. Relire le PID reel avant
                # le test, sinon faux "process died" -> redemarrage complet.
                local dnsmasq_pid
                dnsmasq_pid=$(pidof dnsmasq 2>/dev/null | awk '{print $1}')
                if [ -n "$dnsmasq_pid" ]; then
                    SERVICE_PIDS[dnsmasq]="$dnsmasq_pid"
                fi
                if ! is_process_running "${SERVICE_PIDS[dnsmasq]}"; then
                    log_json ERROR "supervisor" "dnsmasq process died"
                    fail=1
                elif ! nslookup example.com 127.0.0.1 >/dev/null 2>&1 && ! dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
                    log_json ERROR "supervisor" "DNS resolution via 127.0.0.1 failed"
                    fail=1
                fi
            fi

            if [ "$fail" -eq 0 ] && [ "${SERVICE_PIDS[tailscaled]}" -ne 0 ]; then
                if ! is_process_running "${SERVICE_PIDS[tailscaled]}"; then
                    log_json ERROR "supervisor" "tailscaled process died"
                    fail=1
                fi
            fi

            if [ "$fail" -eq 0 ]; then
                update_metrics
                stable_cycles=$((stable_cycles + 1))
                if [ "$stable_cycles" -ge 6 ] && [ "$attempt" -gt 1 ]; then
                    attempt=1
                    stable_cycles=0
                    # METRIC_RESTART_COUNT n'est PAS reinitialise : un counter
                    # Prometheus ne doit jamais decroitre (M1).
                    log_json INFO "supervisor" "services stable - backoff counter reset"
                fi
                continue
            fi

            log_json ERROR "supervisor" "failure detected - leaving keepalive loop" "attempt=${attempt}"
            rm -f "$VPN_HEALTHY_FILE"
            METRIC_VPN_UP=0
            update_metrics
            break
        done

        log_json ERROR "supervisor" "failure detected - restarting services" "attempt=${attempt}"
        rm -f "$VPN_HEALTHY_FILE"
        METRIC_VPN_UP=0
        METRIC_LAST_RESTART_TS=$(date +%s)
        update_metrics

        kill_if_running "${SERVICE_PIDS[vpn]}"
        kill_if_running "${SERVICE_PIDS[privoxy]}"
        kill_if_running "${SERVICE_PIDS[nginx]}"
        kill_if_running "${SERVICE_PIDS[dnsmasq]}"
        kill_if_running "${SERVICE_PIDS[tailscaled]}"
        kill_if_running "${SERVICE_PIDS[unbound]}"

        local pids_to_wait=""
        local pid
        for pid in "${SERVICE_PIDS[vpn]}" "${SERVICE_PIDS[privoxy]}" "${SERVICE_PIDS[nginx]}" "${SERVICE_PIDS[dnsmasq]}" "${SERVICE_PIDS[tailscaled]}" "${SERVICE_PIDS[unbound]}"; do
            if [ -n "$pid" ] && [ "$pid" -ne 0 ]; then
                pids_to_wait="$pids_to_wait $pid"
            fi
        done

        if [ -n "$pids_to_wait" ]; then
            wait $pids_to_wait 2>/dev/null || true
        fi

        cleanup_routes_on_restart

        SERVICE_PIDS[vpn]=0
        SERVICE_PIDS[privoxy]=0
        SERVICE_PIDS[nginx]=0
        SERVICE_PIDS[dnsmasq]=0
        SERVICE_PIDS[tailscaled]=0
        SERVICE_PIDS[unbound]=0

        DOT_RESOLVED_IPS=""
        unset DOT_HOST_IP_MAP
        declare -gA DOT_HOST_IP_MAP=()

        local sleep_s
        sleep_s=$((5 + attempt * 10))
        if [ "$sleep_s" -gt 60 ]; then
            sleep_s=60
        fi

        log_json INFO "supervisor" "stabilization wait ${sleep_s}s" "attempt=${attempt}"
        sleep_wait "$sleep_s"

        # Plafonne la monte du delai de grace : avant, il augmentait de 5 a
        # chaque echec sans limite (M12).
        SKIP_HEALTHCHECK_FIRST_MINUTES=$(( ${SKIP_HEALTHCHECK_FIRST_MINUTES:-0} + 5 ))
        if [ "$SKIP_HEALTHCHECK_FIRST_MINUTES" -gt 15 ]; then
            SKIP_HEALTHCHECK_FIRST_MINUTES=15
        fi
    done
}
