#!/bin/bash
# Supervisor orchestration extracted from start.sh

supervise_all() {
    log_json INFO "supervisor" \
        "Starting supervisor" \
        "version=2.1.0"

    local attempt=0

    validate_environment

    cp "$RESOLV_CONF" /tmp/resolv.conf.bak 2>/dev/null || true

    echo "nameserver ${DNS_SERVER_1}" > "$RESOLV_CONF"
    echo "nameserver ${DNS_SERVER_2}" >> "$RESOLV_CONF"

    while true; do
        attempt=$((attempt + 1))

        METRIC_RESTART_COUNT=$((attempt - 1))
        METRIC_LAST_RESTART_TS=$(date +%s)

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
            sleep 2
        fi

        # Phase 1.5 : Pre-load DoT IPs
        if [ "${ENABLE_DOT:-false}" = "true" ]; then
            preload_dot_ips
        fi

        # Phase 2 : Unbound / DoT
        start_unbound

        if [ "${ENABLE_DOT:-false}" = "true" ] && [ -s "$DOT_FORWARD_ADDRS_FILE" ]; then
            log_json INFO "supervisor" "DoT configured - waiting for stabilization..."
            sleep 3
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

                sleep 2
            done

            if [ "$dns_ready" -ne 1 ]; then
                log_json ERROR "supervisor" "DNS services (unbound/dnsmasq) not ready - retrying"
                kill_if_running "${SERVICE_PIDS[dnsmasq]}"
                kill_if_running "${SERVICE_PIDS[unbound]}"

                SERVICE_PIDS[dnsmasq]=0
                SERVICE_PIDS[unbound]=0

                sleep 5
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

                sleep 1
            done

            if [ "$dns_ready" -ne 1 ]; then
                log_json ERROR "supervisor" "dnsmasq not ready after 15s - retrying"
                kill_if_running "${SERVICE_PIDS[dnsmasq]}"
                SERVICE_PIDS[dnsmasq]=0

                sleep 5
                continue
            fi
        fi

        # Firewall and services
        setup_iptables
        setup_ip6tables
        setup_proxy_routing

        start_privoxy
        start_nginx_auth
        start_vpn_service

        if [ "$attempt" -eq 1 ]; then
            start_metrics
            start_dot_ip_refresh
            start_blocklist_refresh
        fi

        log_json INFO "supervisor" "waiting for VPN tunnel..."

        local tun_ready=0
        if wait_for_vpn_tunnel 30; then
            tun_ready=1
        fi

        if [ "$tun_ready" -eq 1 ]; then
            setup_return_routes
            check_vpn_ip

            log_json INFO "supervisor" "waiting for tunnel to be fully operational..."

            local full_ready=0
            for i in 1 2 3; do
                if check_vpn_ip && nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                    full_ready=1
                    break
                fi
                sleep 5
            done

            if [ "$full_ready" -eq 1 ]; then
                touch "$VPN_HEALTHY_FILE"
                METRIC_VPN_UP=1
                start_tailscale
            else
                log_json WARN "supervisor" "tunnel not fully operational after 15s - skipping Tailscale"
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
        sleep 40

        local fail=0
        local start_time
        start_time=$(date +%s)
        local stable_cycles=0

        log_json INFO "supervisor" "entering keepalive loop - sentinel vpn_healthy will be maintained" "interval=10s"

        local keepalive_cycles=0
        while true; do
            sleep 10
            keepalive_cycles=$((keepalive_cycles + 1))
            fail=0

            local current_time
            local elapsed_minutes
            current_time=$(date +%s)
            elapsed_minutes=$(( (current_time - start_time) / 60 ))

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
                    if [ $((keepalive_cycles % 6)) -eq 0 ]; then
                        log_json DEBUG "supervisor" "tunnel health confirmed" "cycles=${keepalive_cycles}" "vpn_healthy=true"
                    fi
                else
                    rm -f "$VPN_HEALTHY_FILE"
                    METRIC_VPN_UP=0
                    log_json WARN "supervisor" "local DNS health check failed"
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
                elif ! nc -z -w 3 127.0.0.1 3128 >/dev/null 2>&1; then
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
        if [ "$sleep_s" -gt 120 ]; then
            sleep_s=120
        fi

        log_json INFO "supervisor" "stabilization wait ${sleep_s}s" "attempt=${attempt}"
        sleep "$sleep_s"

        SKIP_HEALTHCHECK_FIRST_MINUTES=$(( (${SKIP_HEALTHCHECK_FIRST_MINUTES:-0} + 5) ))
    done
}
