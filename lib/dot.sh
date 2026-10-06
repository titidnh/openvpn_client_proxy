#!/bin/bash
# ============================================================================
# lib/dot.sh - DNS over TLS (DoT) and Unbound management
# Extracted from start.sh
# ============================================================================

# ==========================================================================
# DNS-over-TLS / Unbound
# ============================================================================

dot_ip_map_set() {
    local host="$1"
    local ip="$2"
    local tmp

    DOT_HOST_IP_MAP["$host"]="$ip"

    tmp=$(temp_file "dot_ip_map")

    if [ -f "$DOT_IP_MAP_FILE" ]; then
        grep -v "^${host}=" "$DOT_IP_MAP_FILE" > "$tmp" || true
    fi

    echo "${host}=${ip}" >> "$tmp"
    mv -f "$tmp" "$DOT_IP_MAP_FILE"
}

dot_ip_map_get() {
    local host="$1"

    if [ -n "${DOT_HOST_IP_MAP[$host]:-}" ]; then
        echo "${DOT_HOST_IP_MAP[$host]}"
    elif [ -f "$DOT_IP_MAP_FILE" ]; then
        grep "^${host}=" "$DOT_IP_MAP_FILE" |
            cut -d= -f2- |
            tail -1
    fi
}

preload_dot_ips() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    log_json INFO "preload_dot_ips" \
        "Pre-loading DoT IP mappings at boot"

    local servers="${DOT_DNS_SERVERS}"
    servers=$(echo "$servers" | tr ',' ' ')

    local preload_count=0
    local preload_failed=0

    DOT_RESOLVED_IPS=""
    DOT_HOST_IP_MAP=()

    local entry
    for entry in $servers; do
        local proto host ips ip attempt max_attempts backoff

        proto=$(echo "$entry" | awk -F'://' '{print $1}')
        host=$(echo "$entry" |
            sed 's|^[a-z]*://||' |
            awk -F'[:/]' '{print $1}')

        [ -z "$host" ] && continue

        ips=""
        max_attempts=5
        backoff=1
        
        for attempt in $(seq 1 "$max_attempts"); do
            ips=$(resolve_hostname_all \
                "$host" \
                "$DNS_SERVER_1" \
                "$DNS_SERVER_2" 2>/dev/null || true)

            if [ -n "$ips" ]; then
                break
            fi

            if [ "$attempt" -lt "$max_attempts" ]; then
                sleep "$backoff"
                backoff=$((backoff * 2))
                [ "$backoff" -gt 10 ] && backoff=10
            fi
        done

        if [ -n "$ips" ]; then
            local first_ip=1
            local all_ips=""
            local ip_count=0

            while IFS= read -r ip; do
                [ -z "$ip" ] && continue

                ipt_add_853 "$ip"

                DOT_RESOLVED_IPS="${DOT_RESOLVED_IPS}${ip} "
                all_ips="${all_ips}${ip} "
                ip_count=$((ip_count + 1))

                if [ "$first_ip" -eq 1 ]; then
                    DOT_HOST_IP_MAP["$host"]="$ip"
                    first_ip=0
                fi

                dot_ip_map_set "$host" "$ip"

                log_json INFO "preload_dot_ips" \
                    "pre-loaded DoT hostname IP" \
                    "host=${host}" \
                    "ip=${ip}" \
                    "proto=${proto}"
            done <<< "$ips"

            preload_count=$((preload_count + ip_count))

            if [ "$ip_count" -gt 1 ]; then
                log_json INFO "preload_dot_ips" \
                    "pre-loaded multiple IPs for hostname" \
                    "host=${host}" \
                    "ip_count=${ip_count}"
            fi
        else
            preload_failed=$((preload_failed + 1))

            log_json WARN "preload_dot_ips" \
                "could not pre-load DoT hostname" \
                "host=${host}" \
                "max_attempts=${max_attempts}"
        fi
    done

    if [ "$preload_count" -gt 0 ]; then
        log_json INFO "preload_dot_ips" \
            "DoT pre-loading complete - IPs cached for firewall" \
            "total_ips=${preload_count}" \
            "failed_hostnames=${preload_failed}"
    else
        log_json WARN "preload_dot_ips" \
            "DoT pre-loading failed - no IPs resolved" \
            "failed_hostnames=${preload_failed}"
    fi
}

parse_dot_servers() {
    log_json INFO "parse_dot_servers" "Parsing DoT servers"

    local servers="${DOT_DNS_SERVERS}"
    servers=$(echo "$servers" | tr ',' ' ')

    local tmp_map tmp_forward
    tmp_map=$(temp_file "dot_ip_map")
    tmp_forward=$(temp_file "dot_forward_addrs")

    DOT_RESOLVED_IPS=""
    DOT_HOST_IP_MAP=()

    local entry
    for entry in $servers; do
        local proto host ips ip attempt max_attempts backoff

        proto=$(echo "$entry" | awk -F'://' '{print $1}')
        host=$(echo "$entry" |
            sed 's|^[a-z]*://||' |
            awk -F'[:/]' '{print $1}')

        [ -z "$host" ] && continue

        ips=""
        max_attempts=5
        backoff=1
        
        for attempt in $(seq 1 "$max_attempts"); do
            ips=$(resolve_hostname_all \
                "$host" \
                "$DNS_SERVER_1" \
                "$DNS_SERVER_2" 2>/dev/null || true)

            if [ -n "$ips" ]; then
                if [ "$attempt" -gt 1 ]; then
                    log_json INFO "parse_dot_servers" \
                        "resolved after retry" \
                        "host=${host}" \
                        "ip_count=$(echo "$ips" | wc -l)" \
                        "attempts=${attempt}"
                fi
                break
            fi

            if [ "$attempt" -lt "$max_attempts" ]; then
                log_json WARN "parse_dot_servers" \
                    "resolve attempt failed, retrying" \
                    "host=${host}" \
                    "attempt=${attempt}/${max_attempts}" \
                    "wait=${backoff}s"

                sleep "$backoff"
                backoff=$((backoff * 2))

                if [ "$backoff" -gt 10 ]; then
                    backoff=10
                fi
            fi
        done

        # Repli fail-safe sur le cache persistant : apres le verrouillage
        # final le port 53 externe est bloque (mode DoT), la re-resolution
        # directe est donc impossible lors d un redemarrage du superviseur.
        # Ces IPs ont ete validees au bootstrap ; unbound verifie de toute
        # facon le certificat TLS contre le hostname du forward-addr (#host).
        # Sans ce repli, tout redemarrage de la boucle superviseur laissait
        # DoT mort ("no valid DoT servers parsed") en boucle infinie.
        if [ -z "$ips" ]; then
            ips=$(grep "^${host}=" "$DOT_IP_MAP_FILE" 2>/dev/null |
                cut -d= -f2- || true)

            if [ -n "$ips" ]; then
                log_json WARN "parse_dot_servers" \
                    "resolve failed - using cached DoT IPs" \
                    "host=${host}" \
                    "ip_count=$(printf '%s\n' "$ips" | wc -l)"
            fi
        fi

        if [ -n "$ips" ]; then
            local first_ip=1
            local all_ips=""

            while IFS= read -r ip; do
                [ -z "$ip" ] && continue

                ipt_add_853 "$ip"

                DOT_RESOLVED_IPS="${DOT_RESOLVED_IPS}${ip} "
                all_ips="${all_ips}${ip} "

                if [ "$first_ip" -eq 1 ]; then
                    DOT_HOST_IP_MAP["$host"]="$ip"
                    first_ip=0
                fi

                echo "${host}=${ip}" >> "$tmp_map"

                if [ "$proto" = "https" ]; then
                    echo "        forward-addr: ${ip}@443#${host}" \
                        >> "$tmp_forward"
                else
                    echo "        forward-addr: ${ip}@853#${host}" \
                        >> "$tmp_forward"
                fi

                log_json INFO "parse_dot_servers" \
                    "resolved" \
                    "host=${host}" \
                    "ip=${ip}" \
                    "proto=${proto}"
            done <<< "$ips"
        else
            log_json WARN "parse_dot_servers" \
                "could not resolve after max retries, skipping" \
                "host=${host}" \
                "max_attempts=${max_attempts}"
        fi
    done

    if [ -s "$tmp_map" ]; then
        mv -f "$tmp_map" "$DOT_IP_MAP_FILE"
    else
        rm -f "$tmp_map"
    fi

    if [ -s "$tmp_forward" ]; then
        mv -f "$tmp_forward" "$DOT_FORWARD_ADDRS_FILE"
    else
        rm -f "$tmp_forward"
    fi
}

configure_unbound() {
    log_json INFO "configure_unbound" \
        "Configuring Unbound for DoT"

    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    if ! command_exists unbound; then
        log_json ERROR "configure_unbound" \
            "unbound binary not found - DoT disabled"
        return 1
    fi

    local conf_file
    conf_file=$(temp_file "unbound")

    parse_dot_servers

    if [ ! -s "$DOT_FORWARD_ADDRS_FILE" ]; then
        log_json ERROR "configure_unbound" \
            "no valid DoT servers parsed - DoT disabled"
        rm -f "$conf_file"
        return 1
    fi

    local forward_addrs
    forward_addrs=$(cat "$DOT_FORWARD_ADDRS_FILE")

    local dnssec_mode="val-permissive-mode: yes"

    if [ "${ENABLE_DNSSEC:-false}" = "true" ]; then
        dnssec_mode="val-permissive-mode: no"

        mkdir -p /var/lib/unbound
        chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true

        unbound-anchor \
            -a /var/lib/unbound/root.key \
            2>/dev/null || true

        log_json INFO "configure_unbound" \
            "DNSSEC strict validation enabled"
    fi

    local tls_cert_bundle="/etc/ssl/certs/ca-certificates.crt"

    if [ -n "${DOT_TLS_CERT_BUNDLE:-}" ] &&
        [ -f "${DOT_TLS_CERT_BUNDLE}" ]; then

        tls_cert_bundle="${DOT_TLS_CERT_BUNDLE}"

        log_json INFO "configure_unbound" \
            "TLS cert bundle (pinning)" \
            "bundle=${tls_cert_bundle}"
    fi

    local split_zones=""

    if [ -n "${DNS_SPLIT:-}" ]; then
        local split_entries
        split_entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')

        local entry
        for entry in $split_entries; do
            local domain resolver res_ip res_port

            domain="${entry%%=*}"
            resolver="${entry#*=}"
            res_ip="${resolver%%:*}"
            res_port="${resolver##*:}"

            [ "$res_port" = "$res_ip" ] && res_port="53"
            [ -z "$domain" ] || [ -z "$res_ip" ] && continue

            split_zones="${split_zones}
forward-zone:
    name: \"${domain}\"
    forward-tls-upstream: no
    forward-addr: ${res_ip}@${res_port}"

            log_json INFO "configure_unbound" \
                "split DNS zone" \
                "domain=${domain}" \
                "resolver=${res_ip}:${res_port}"
        done
    fi

    mkdir -p /etc/unbound /var/lib/unbound
    chown -R unbound:unbound \
        /etc/unbound \
        /var/lib/unbound \
        2>/dev/null || true

    chmod 0755 /etc/unbound 2>/dev/null || true

    cat > "$conf_file" <<EOF
server:
    interface: 127.0.0.1
    port: 5053
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    do-not-query-localhost: no

    verbosity: 1
    logfile: ""

    hide-identity: yes
    hide-version: yes

    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    use-caps-for-id: yes
    unwanted-reply-threshold: 10000000

    cache-min-ttl: 60
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 86400

    tls-cert-bundle: ${tls_cert_bundle}

    ${dnssec_mode}
EOF

    if [ "${ENABLE_DNS_BLOCKLIST:-false}" = "true" ] &&
        [ -s "$DNS_BLOCKLIST_COMPILED_UNBOUND" ]; then

        echo "    include: \"${DNS_BLOCKLIST_COMPILED_UNBOUND}\"" \
            >> "$conf_file"

        log_json INFO "configure_unbound" \
            "blocage DNS pub/tracking actif" \
            "fichier=${DNS_BLOCKLIST_COMPILED_UNBOUND}"
    fi

    if [ "${ENABLE_DNSSEC:-false}" = "true" ] &&
        [ -f /var/lib/unbound/root.key ]; then

        echo "    auto-trust-anchor-file: /var/lib/unbound/root.key" \
            >> "$conf_file"
    fi

    cat >> "$conf_file" <<EOF

forward-zone:
    name: "."
    forward-tls-upstream: yes
${forward_addrs}
EOF

    [ -n "$split_zones" ] && echo "$split_zones" >> "$conf_file"

    if command_exists unbound-checkconf; then
        if ! unbound-checkconf "$conf_file" \
            >/tmp/unbound.checkconf 2>&1; then

            log_json ERROR "configure_unbound" \
                "unbound config test failed"

            cat /tmp/unbound.checkconf >&2 || true

            mv -f "$conf_file" \
                "${UNBOUND_CONF}.invalid" \
                2>/dev/null || true

            chmod 0644 "${UNBOUND_CONF}.invalid" \
                2>/dev/null || true

            chown unbound:unbound \
                "${UNBOUND_CONF}.invalid" \
                2>/dev/null || true

            cp -f "${UNBOUND_CONF}.invalid" \
                "$UNBOUND_CONF" \
                2>/dev/null || true
        fi
    else
        log_json WARN "configure_unbound" \
            "unbound-checkconf not found - skipping syntax check"
    fi

    if [ -f "$conf_file" ]; then
        mv -f "$conf_file" "$UNBOUND_CONF" 2>/dev/null || true
    fi

    chmod 0644 "$UNBOUND_CONF" 2>/dev/null || true
    chown unbound:unbound "$UNBOUND_CONF" 2>/dev/null || true

    touch /var/log/unbound.log 2>/dev/null || true
    chown unbound:unbound \
        /var/log/unbound.log \
        2>/dev/null || true

    chmod 0644 "$UNBOUND_CONF" 2>/dev/null || true

    log_json INFO "configure_unbound" \
        "config written" \
        "dnssec=${ENABLE_DNSSEC:-false}" \
        "tls_bundle=${tls_cert_bundle}" \
        "split_dns=${DNS_SPLIT:-none}"
}

test_unbound_dns_robust() {
    local attempt=0
    local max_attempts=6

    while [ "$attempt" -lt "$max_attempts" ]; do
        attempt=$((attempt + 1))

        if command_exists dig; then
            if timeout 6 dig \
                @127.0.0.1 \
                -p 5053 \
                +tries=1 \
                +timeout=4 \
                example.com \
                +short \
                2>/dev/null | grep -q .; then
                return 0
            fi
        elif command_exists nslookup; then
            if timeout 6 nslookup \
                example.com \
                127.0.0.1 \
                2>/dev/null |
                grep -q "Name:"; then
                return 0
            fi
        fi

        if [ "$attempt" -lt "$max_attempts" ]; then
            sleep 1
        fi
    done

    return 1
}

start_unbound() {
    log_json INFO "start_unbound" "Starting Unbound"

    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    if ! wait_for_dns_ready 30; then
        log_json WARN "start_unbound" \
            "classic DNS not ready - delaying unbound"
        return 0
    fi

    configure_unbound || return 0

    pkill -9 -f "^unbound -d" 2>/dev/null || true
    sleep 1

    unbound -d -c "$UNBOUND_CONF" &
    SERVICE_PIDS[unbound]=$!

    local max_wait=10

    if [ "${ENABLE_DNSSEC:-false}" = "true" ]; then
        max_wait=30

        log_json INFO "start_unbound" \
            "DNSSEC enabled - extended startup timeout" \
            "timeout=${max_wait}s"
    fi

    local bound=0
    local i

    for i in $(seq 1 "$max_wait"); do
        if ! kill -0 "${SERVICE_PIDS[unbound]}" 2>/dev/null; then
            log_json WARN "start_unbound" \
                "unbound exited during startup" \
                "pid=${SERVICE_PIDS[unbound]}"
            break
        fi

        if nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
            if test_unbound_dns_robust; then
                bound=1
                break
            fi
        fi

        sleep 1
    done

    if [ "$bound" -eq 1 ]; then
        reconfigure_dnsmasq_to_unbound

        METRIC_DOT_ACTIVE=1

        log_json INFO "start_unbound" \
            "started - DoT active" \
            "pid=${SERVICE_PIDS[unbound]}" \
            "port=5053"
    else
        log_json WARN "start_unbound" \
            "unbound not ready after startup window" \
            "timeout=${max_wait}s" \
            "pid=${SERVICE_PIDS[unbound]:-unknown}"

        METRIC_DOT_ACTIVE=0
    fi
}

restart_unbound_if_needed() {
    if [ "${ENABLE_DOT:-false}" != "true" ]; then
        return 0
    fi

    if ! kill -0 "${SERVICE_PIDS[unbound]}" 2>/dev/null; then
        log_json WARN "supervisor" \
            "unbound process died - restarting immediately"

        pkill -9 -f "^unbound" 2>/dev/null || true
        sleep 1

        configure_unbound || return 1

        unbound -d -c "$UNBOUND_CONF" &
        SERVICE_PIDS[unbound]=$!

        reconfigure_dnsmasq_to_unbound

        log_json INFO "supervisor" \
            "unbound restarted" \
            "pid=${SERVICE_PIDS[unbound]}"

        return 1
    fi

    if ! nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
        log_json WARN "supervisor" \
            "unbound port unresponsive - hard restart"

        pkill -9 -f "^unbound" 2>/dev/null || true
        sleep 2

        configure_unbound || return 1

        unbound -d -c "$UNBOUND_CONF" &
        SERVICE_PIDS[unbound]=$!

        reconfigure_dnsmasq_to_unbound

        return 1
    fi

    return 0
}

_dot_refresh_loop() {
    local interval="${DOT_IP_REFRESH_INTERVAL:-3600}"

    log_json INFO "dot_refresh" \
        "Starting periodic IP refresh" \
        "interval=${interval}s"

    while true; do
        sleep "$interval"

        local dot_changed=0
        local servers="${DOT_DNS_SERVERS}"

        servers=$(echo "$servers" | tr ',' ' ')

        local entry
        for entry in $servers; do
            local host new_ips old_ips

            host=$(echo "$entry" |
                sed 's|^[a-z]*://||' |
                awk -F'[:/]' '{print $1}')

            [ -z "$host" ] && continue

            new_ips=$(resolve_hostname_all \
                "$host" \
                "$DNS_SERVER_1" \
                "$DNS_SERVER_2")

            old_ips=$(grep "^${host}=" "$DOT_IP_MAP_FILE" 2>/dev/null | cut -d= -f2- | sort | tr '\n' ' ' || true)

            if [ -z "$new_ips" ]; then
                log_json WARN "dot_refresh" \
                    "re-resolve failed" \
                    "host=${host}"
                continue
            fi

            new_ips_sorted=$(echo "$new_ips" | sort | tr '\n' ' ')
            old_ips_sorted=$(echo "$old_ips" | sort)

            if [ "$new_ips_sorted" = "$old_ips_sorted" ]; then
                log_json INFO "dot_refresh" \
                    "IPs unchanged" \
                    "host=${host}" \
                    "ip_count=$(echo "$new_ips" | wc -l)"
                continue
            fi

            log_json INFO "dot_refresh" \
                "IP(s) changed - preparing refresh" \
                "host=${host}" \
                "old_count=$(echo "$old_ips" | wc -w)" \
                "new_count=$(echo "$new_ips" | wc -l)"

            if configure_unbound; then
                local ub_pid

                ub_pid=$(pidof unbound | awk '{print $1}' || true)

                if [ -n "$ub_pid" ]; then
                    log_json INFO "dot_refresh" \
                        "Reloading unbound after IP(s) change" \
                        "pid=${ub_pid}" \
                        "host=${host}"

                    kill -HUP "$ub_pid" 2>/dev/null || true

                    local reload_ok=0
                    local reload_max_wait=10
                    local reload_attempt

                    for reload_attempt in $(seq 1 "$reload_max_wait"); do
                        sleep 1

                        if ! kill -0 "$ub_pid" 2>/dev/null; then
                            log_json WARN "dot_refresh" \
                                "unbound died during reload" \
                                "host=${host}"
                            break
                        fi

                        if test_unbound_dns_robust; then
                            reload_ok=1
                            break
                        fi
                    done

                    if [ "$reload_ok" -eq 1 ]; then
                        dot_changed=1

                        local stale_ip
                        for stale_ip in $old_ips; do
                            if ! printf '%s\n' "$new_ips" | grep -qx "$stale_ip"; then
                                ipt_del_853 "$stale_ip"

                                log_json INFO "dot_refresh" \
                                    "removed stale 853 rule" \
                                    "host=${host}" \
                                    "ip=${stale_ip}"
                            fi
                        done

                        {
                            grep -v "^${host}=" "$DOT_IP_MAP_FILE" 2>/dev/null || true
                            echo "$new_ips" | while read -r ip; do
                                [ -n "$ip" ] && echo "${host}=${ip}"
                            done
                        } > "${DOT_IP_MAP_FILE}.tmp"
                        mv -f "${DOT_IP_MAP_FILE}.tmp" "$DOT_IP_MAP_FILE"

                        log_json INFO "dot_refresh" \
                            "unbound reloaded successfully" \
                            "pid=${ub_pid}" \
                            "host=${host}" \
                            "new_ip_count=$(echo "$new_ips" | wc -l)"
                    else
                        log_json WARN "dot_refresh" \
                            "unbound reload validation timeout" \
                            "host=${host}"
                    fi
                else
                    log_json WARN "dot_refresh" \
                        "unbound not running while refreshing config"
                fi
            else
                log_json WARN "dot_refresh" \
                    "failed to regenerate unbound config after DoT IP change"
            fi
        done

        if [ "$dot_changed" -eq 1 ]; then
            log_json INFO "dot_refresh" \
                "DoT IP refresh complete" \
                "changed=1"
        fi
    done
}

start_dot_ip_refresh() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    local interval="${DOT_IP_REFRESH_INTERVAL:-3600}"

    log_json INFO "dot_refresh" \
        "starting periodic IP refresh" \
        "interval=${interval}s"

    _dot_refresh_loop &

    SERVICE_PIDS[dot_refresh]=$!

    log_json INFO "dot_refresh" \
        "refresh loop started" \
        "pid=${SERVICE_PIDS[dot_refresh]}"
}

