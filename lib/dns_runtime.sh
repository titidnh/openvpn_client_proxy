#!/bin/bash
# DNS runtime helpers (dnsmasq/unbound/blocklist hooks)

configure_dnsmasq() {
    log_json INFO "configure_dnsmasq" \
        "Configuring dnsmasq"

    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        cat > "$DNSMASQ_CONF" <<EOF
# Generated at startup - DNS-over-TLS mode via local unbound
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=127.0.0.1#5053
cache-size=1000
log-facility=/dev/null
EOF

        log_json INFO "configure_dnsmasq" \
            "DoT mode - upstream: 127.0.0.1#5053"
    else
        cat > "$DNSMASQ_CONF" <<EOF
# Generated at startup from DNS_SERVER_1 / DNS_SERVER_2
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=${DNS_SERVER_1}
server=${DNS_SERVER_2}
cache-size=1000
log-facility=/dev/null
EOF

        if [ -n "${DNS_SPLIT:-}" ]; then
            local entries
            entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')

            local entry
            for entry in $entries; do
                local domain resolver res_ip res_port

                domain="${entry%%=*}"
                resolver="${entry#*=}"
                res_ip="${resolver%%:*}"
                res_port="${resolver##*:}"

                [ "$res_port" = "$res_ip" ] && res_port="53"
                [ -z "$domain" ] || [ -z "$res_ip" ] && continue

                echo "server=/${domain}/${res_ip}#${res_port}" \
                    >> "$DNSMASQ_CONF"

                log_json INFO "configure_dnsmasq" \
                    "split DNS" \
                    "domain=${domain}" \
                    "resolver=${res_ip}:${res_port}"
            done
        fi

        log_json INFO "configure_dnsmasq" \
            "upstream: ${DNS_SERVER_1}, ${DNS_SERVER_2}"
    fi

    if [ "${ENABLE_DNS_BLOCKLIST:-false}" = "true" ] && [ -s "$DNS_BLOCKLIST_COMPILED_DNSMASQ" ]; then
        echo "conf-file=${DNS_BLOCKLIST_COMPILED_DNSMASQ}" >> "$DNSMASQ_CONF"

        log_json INFO "configure_dnsmasq" \
            "blocage DNS pub/tracking actif" \
            "fichier=${DNS_BLOCKLIST_COMPILED_DNSMASQ}"
    fi
}

start_dnsmasq() {
    log_json INFO "start_dnsmasq" "Starting dnsmasq"

    configure_dnsmasq

    echo "nameserver 127.0.0.1" > "$RESOLV_CONF" || {
        echo "nameserver 127.0.0.1" > /tmp/resolv.conf
        mount --bind /tmp/resolv.conf "$RESOLV_CONF" || true
    }

    if ! dnsmasq --test --conf-file="$DNSMASQ_CONF" >/tmp/dnsmasq.test 2>&1; then
        log_json ERROR "start_dnsmasq" "config test failed"
        sed -n '1,200p' /tmp/dnsmasq.test >&2 || true
        return 0
    fi

    dnsmasq --no-daemon --conf-file="$DNSMASQ_CONF" --log-facility=- &
    SERVICE_PIDS[dnsmasq]=$!

    local bound=0
    local i

    for i in $(seq 1 10); do
        if nc -z -w 1 127.0.0.1 53 >/dev/null 2>&1; then
            if nslookup example.com 127.0.0.1 >/dev/null 2>&1 || \
               dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
                bound=1
                break
            fi
        fi

        sleep 1
    done

    if [ "$bound" -eq 1 ]; then
        log_json INFO "start_dnsmasq" "started" "pid=${SERVICE_PIDS[dnsmasq]}" "port=53"
    else
        log_json ERROR "start_dnsmasq" "dnsmasq did not become fully operational"
    fi
}

wait_for_dns_ready() {
    local max_wait="${1:-30}"

    log_json INFO "wait_for_dns_ready" "waiting for local DNS" "timeout=${max_wait}s"

    local i
    for i in $(seq 1 "$max_wait"); do
        if nslookup example.com 127.0.0.1 >/dev/null 2>&1 || \
           dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
            log_json INFO "wait_for_dns_ready" "local DNS is responsive" "after=${i}s"
            return 0
        fi
        sleep 1
    done

    log_json WARN "wait_for_dns_ready" "local DNS did not become ready" "timeout=${max_wait}s"
    return 1
}

reconfigure_dnsmasq_to_unbound() {
    log_json INFO "reconfigure_dnsmasq" "Reconfiguring dnsmasq to use unbound"
    kill_if_running "${SERVICE_PIDS[dnsmasq]}"
    SERVICE_PIDS[dnsmasq]=0
    start_dnsmasq
}
