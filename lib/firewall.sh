#!/bin/bash
# ============================================================================
# lib/firewall.sh - Firewall rule management (iptables/ip6tables)
# ============================================================================
# This module handles all firewall configuration including:
# - IPv4/IPv6 iptables rules
# - Kill switch and DNS leak prevention
# - Early lockdown at startup (no ACCEPT-by-default window)
# - Port 853 (DoT) firewall rules (idempotent)
# - Return routes configuration
#
# NOTE: ce fichier ne doit contenir qu'UNE SEULE definition de chaque fonction
# (regression C3 : trois copies concatenees existaient auparavant ; en Bash la
# derniere definition ecrase silencieusement les precedentes).
# ============================================================================

# ===========================================================================
# Helpers for IPv6 support - wrapper around ip6tables
# ===========================================================================

# Wrapper ip6tables : code retour FIDELE a ip6tables (R5). L'ancienne
# version avalait les erreurs et cassait les tests d'existence (-C) :
# "ipt6 -C ... || ipt6 -A ..." ne posait jamais la regle.
# Si ip6tables n'existe pas ou si l'IPv6 est absent du noyau, on retourne 0
# sans rien faire (pas d'IPv6 a proteger dans ce cas) mais on alerte une fois.
IPT6_WARNED=0
ipt6() {
    if ! command -v ip6tables &>/dev/null; then
        return 0
    fi

    # B4 : l'ancienne version faisait "if ip6tables ...; then return 0; fi;
    # local rc=$?" - or $? apres un "if" faux vaut 0, donc rc etait TOUJOURS
    # 0 et ipt6 ne signalait jamais d'echec (les tests -C donnaient faux
    # positifs, les regles 853 IPv6 n'etaient jamais posees).
    local rc=0
    ip6tables "$@" 2>/dev/null || rc=$?
    [ "$rc" -eq 0 ] && return 0

    # ip6tables absent du noyau : echec systematique, une seule alerte
    if ! ip6tables -L -n >/dev/null 2>&1; then
        if [ "$IPT6_WARNED" -eq 0 ]; then
            IPT6_WARNED=1
            log_json WARN "ipt6" "ip6tables unusable on this kernel - IPv6 rules not enforced"
        fi
        return 0
    fi
    return "$rc"
}

# Variante fail-closed : a utiliser pour les commandes critiques (politiques
# DROP). Si ip6tables est utilisable mais que la commande echoue, on logue
# une ERREUR et on retourne 1 pour que l'appelant arrete le demarrage (H4).
ipt6_must() {
    ipt6 "$@" || {
        log_json ERROR "ipt6" "ip6tables critical command failed" "cmd=$*"
        return 1
    }
    return 0
}


# ===========================================================================
# DoT (DNS over TLS) - Firewall port 853 rules
# ===========================================================================

ipt_add_853() {
    local ip="$1"
    # Idempotent : verifier (-C) avant d'ajouter (-A), sinon chaque refresh
    # DoT empile des regles dupliquees (regression C3).
    if [[ "$ip" =~ : ]]; then
        ipt6 -C OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null ||
            ipt6 -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
    else
        iptables -C OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null ||
            iptables -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
    fi
}

ipt_del_853() {
    local ip="$1"

    if [[ "$ip" =~ : ]]; then
        ipt6 -D OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
    else
        iptables -D OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
    fi
}

# ===========================================================================
# Early lockdown : a appeler le plus tot possible au demarrage (avant la
# phase blocklist/dnsmasq/unbound). Sans cela, le conteneur tourne avec la
# politique par defaut ACCEPT et les telechargements de blocklist sortent
# avec l'IP reelle du reseau physique (fenetre de fuite, H5).
# tcp/443 sortant reste temporairement autorise (telechargement des
# blocklists avant l'existence du tunnel). setup_iptables retire ce
# bootstrap des que le kill switch complet est pose.
# ===========================================================================
firewall_early_lockdown() {
    log_json INFO "firewall_early_lockdown" "Applying early DROP policies"

    # §4-6 (H4) : si une politique DROP ne peut pas etre posee (module
    # absent, CAP_NET_ADMIN manquante), le conteneur tournerait en ACCEPT
    # par defaut SANS kill switch et sans erreur. Echec explicite.
    if ! iptables -P INPUT DROP || ! iptables -P FORWARD DROP || ! iptables -P OUTPUT DROP; then
        log_json ERROR "firewall_early_lockdown" \
            "cannot set DROP policies - kill switch impossible on this kernel" \
            "hint=run with NET_ADMIN capability and iptables support"
        return 1
    fi
    iptables -F
    iptables -X
    iptables -t nat -F

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # DNS bootstrap (resolution des hotes VPN/DoT)
    local dns
    for dns in "${DNS_SERVER_1:-}" "${DNS_SERVER_2:-}"; do
        [[ "$dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
    done

    # Telechargement blocklists (avant tunnel), seulement si necessaire.
    # La capture d'IP reelle n'ouvre QUE 1.1.1.1 en 443 (§4-5 : l'ancienne
    # regle laissait sortir tcp/443 vers TOUTE destination par defaut).
    if [ "${COLLECT_REAL_IP:-false}" = "true" ]; then
        iptables -A OUTPUT -p tcp -d 1.1.1.1 --dport 443 -j ACCEPT
    fi
    if [ "${ENABLE_DNS_BLOCKLIST:-false}" = "true" ]; then
        iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    fi

    # R2/R6 : resoudre les IPs des remotes VPN MAINTENANT, pendant que le DNS
    # bootstrap (53 vers DNS_SERVER_*) est encore autorise. En mode DoT ces
    # ACCEPT disparaissent au verrouillage final : resoudre apres echouerait
    # et declencherait le fallback par port (brèche). TOUTES les IP sont
    # conservees (round-robin DNS, R6) : a la reconnexion OpenVPN pourra
    # joindre n'importe laquelle.
    # 3.1 : plusieurs remote peuvent partager un hostname (multi-remote
    # meme serveur) - resoudre chaque hostname UNE SEULE fois (sur un DNS
    # muet, chaque resolution coute plusieurs secondes).
    declare -A RESOLVE_CACHE
    # 3.1-v5 : NE PAS appeler via une substitution de processus (< <(...)) -
    # le sous-shell perdrait l'ecriture du cache. On alimente le cache dans
    # le shell parent, puis on lit RESOLVE_CACHE directement.
    resolve_cached() {
        local host="$1"
        [ -n "${RESOLVE_CACHE[$host]+set}" ] ||
            RESOLVE_CACHE[$host]="$(resolve_vpn_ips "$host" "$DNS_SERVER_1" "$DNS_SERVER_2" 2>/dev/null || true)"
        return 0
    }
    if [ "${VPN_TYPE:-openvpn}" = "wireguard" ]; then
        local wg_host wg_port wg_ip
        while read -r wg_host wg_port; do
            [ -n "${wg_host:-}" ] || continue
            wg_host="${wg_host#[}"
            wg_host="${wg_host%]}"
            [ -n "${wg_port:-}" ] || wg_port=51820
            if [[ "$wg_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$wg_host" =~ : ]]; then
                VPN_REMOTE_IPS="$VPN_REMOTE_IPS $wg_host|${wg_port}|udp"
            else
                resolve_cached "$wg_host"
                while read -r wg_ip; do
                    [ -n "${wg_ip:-}" ] || continue
                    VPN_REMOTE_IPS="$VPN_REMOTE_IPS $wg_ip|${wg_port}|udp"
                done <<< "${RESOLVE_CACHE[$wg_host]}"
            fi
        done < <(get_wireguard_endpoint "${VPN_DIR}/wg0.conf")
    else
        local r_host r_port r_proto r_ip
        while read -r r_host r_port r_proto; do
            [ -n "${r_host:-}" ] || continue
            if [[ "$r_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$r_host" =~ : ]]; then
                VPN_REMOTE_IPS="$VPN_REMOTE_IPS $r_host|$r_port|$r_proto"
            else
                resolve_cached "$r_host"
                while read -r r_ip; do
                    [ -n "${r_ip:-}" ] || continue
                    VPN_REMOTE_IPS="$VPN_REMOTE_IPS $r_ip|$r_port|$r_proto"
                done <<< "${RESOLVE_CACHE[$r_host]}"
            fi
        done < <(parse_vpn_remotes "$VPN_CONF")
    fi
    export VPN_REMOTE_IPS="${VPN_REMOTE_IPS# }"
    # v8 : exporter la carte hostname -> IPs resolues pour qu OpenVPN
    # utilise EXACTEMENT les IPs autorisees au pare-feu. Sinon OpenVPN
    # re-resout le hostname au demarrage et peut obtenir une autre IP
    # du round-robin DNS -> bloquee par le kill switch (write UDPv4:
    # Operation not permitted).
    local map_host map_ips remote_map=""
    for map_host in "${!RESOLVE_CACHE[@]}"; do
        map_ips=""
        local m_ip
        for m_ip in ${RESOLVE_CACHE[$map_host]}; do
            map_ips="${map_ips},${m_ip}"
        done
        map_ips="${map_ips#,}"
        [ -n "$map_ips" ] && remote_map="$remote_map $map_host=$map_ips"
    done
    [ -n "$remote_map" ] && export VPN_REMOTE_MAP="${remote_map# }"
    if [ -n "$VPN_REMOTE_IPS" ]; then
        log_json INFO "firewall_early_lockdown" \
            "VPN remotes resolved during bootstrap" \
            "endpoints=$(echo $VPN_REMOTE_IPS | wc -w)"
    else
        log_json WARN "firewall_early_lockdown" \
            "no VPN remote resolved during bootstrap"
    fi

    ipt6 -P INPUT DROP
    ipt6 -P FORWARD DROP
    ipt6 -P OUTPUT DROP
    ipt6 -A INPUT -i lo -j ACCEPT
    ipt6 -A OUTPUT -o lo -j ACCEPT
    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A OUTPUT -p tcp --dport 443 -j ACCEPT

    log_json INFO "firewall_early_lockdown" "Early lockdown active (bootstrap: DNS + tcp/443)"
}

# Interface physique par defaut (eth0 en general, jamais tun/tap/wg)
# Usage: get_physical_iface
get_physical_iface() {
    ip route show default 2>/dev/null |
        grep -vE 'tun[0-9]*|tap[0-9]*|wg[0-9]*' |
        awk '{print $5; exit}'
}

# ===========================================================================
# IPv4 Firewall - Kill switch + DNS leak prevention
# ===========================================================================

# v10 (dette "IP figees") : re-resolution periodique des remotes VPN.
# Le pare-feu et l'epinglage OpenVPN figent les IP au bootstrap ; si le
# fournisseur change d IP pendant la vie du conteneur, la connexion
# tombait dans le kill switch jusqu au redemarrage. Cette fonction :
# 1. re-resout chaque hostname de VPN_REMOTE_MAP via le DNS LOCAL (127.0.0.1
#    en DoT, DNS_SERVER_* sinon) - le port 53 externe est bloque apres le
#    verrouillage, on ne re-resout JAMAIS vers l exterieur en clair ;
# 2. pose les nouvelles regles iptables AVANT de retirer les anciennes
#    (zero interruption, meme approche que dot_refresh) ;
# 3. met a jour VPN_REMOTE_IPS/VPN_REMOTE_MAP pour que le prochain
#    (re)demarrage d openvpn.sh epingle exactement ces IP.
# Fail-safe : en cas d echec de resolution, les anciennes IP sont
# CONSERVEES (jamais de fail-open). Retour 1 = IP changees, le
# superviseur doit redemarrer le VPN pour re-epingler la nouvelle carte.
# Usage: refresh_vpn_remote_ips
refresh_vpn_remote_ips() {
    [ -n "${VPN_REMOTE_MAP:-}" ] || return 0

    local phys_iface
    phys_iface=$(get_physical_iface)
    phys_iface="${phys_iface:-eth0}"

    local old_map="$VPN_REMOTE_MAP"
    local new_map="" changed=0
    local entry host old_ips new_ips
    local ip rest port proto

    for entry in $old_map; do
        host="${entry%%=*}"
        old_ips="${entry#*=}"
        [ -n "$host" ] && [ -n "$old_ips" ] || continue

        if [ "${ENABLE_DOT:-false}" = "true" ]; then
            new_ips=$(resolve_vpn_ips "$host" 127.0.0.1 2>/dev/null || true)
        else
            new_ips=$(resolve_vpn_ips "$host" "$DNS_SERVER_1" "$DNS_SERVER_2" 2>/dev/null || true)
        fi

        if [ -z "$(echo "$new_ips" | tr -d '[:space:]')" ]; then
            log_json WARN "vpn_remote_refresh" \
                "re-resolve failed - keeping old IPs" \
                "host=${host}"
            new_map="${new_map} ${entry}"
            continue
        fi

        local old_sorted new_sorted
        old_sorted=$(printf '%s\n' "$old_ips" | tr ',' '\n' | sort | tr '\n' ' ')
        new_sorted=$(printf '%s\n' "$new_ips" | sort | tr '\n' ' ')

        if [ "$old_sorted" = "$new_sorted" ]; then
            new_map="${new_map} ${entry}"
            continue
        fi

        log_json INFO "vpn_remote_refresh" \
            "VPN remote IPs changed - updating firewall" \
            "host=${host}" \
            "old=${old_ips}" \
            "new=$(echo "$new_ips" | tr '\n' ',')"
        changed=1

        # 1. POSER les nouvelles regles d abord (IP x ports/protos connus).
        for ip in $(printf '%s\n' "$new_ips"); do
            for endpoint in ${VPN_REMOTE_IPS:-}; do
                rest="${endpoint#*|}"
                port="${rest%%|*}"
                proto="${rest#*|}"
                [ "${endpoint%%|*}" = "$ip" ] && [ -n "$port" ] && [ -n "$proto" ] || continue
                if [[ "$ip" =~ : ]]; then
                    ipt6 -A OUTPUT -o "$phys_iface" -d "$ip" -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
                else
                    iptables -A OUTPUT -o "$phys_iface" -d "$ip" -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
                fi
            done
        done

        local comma_ips=""
        for ip in $(printf '%s\n' "$new_ips"); do
            comma_ips="${comma_ips},${ip}"
        done
        new_map="${new_map} ${host}=${comma_ips#,}"
    done

    new_map="${new_map# }"
    [ -n "$new_map" ] && export VPN_REMOTE_MAP="$new_map"

    if [ "$changed" -eq 0 ]; then
        log_json DEBUG "vpn_remote_refresh" "VPN remote IPs unchanged"
        return 0
    fi

    # 2. Retirer les anciennes regles qui ne sont plus dans la nouvelle
    #    carte (les nouvelles regles ont ete posees a l etape 1).
    local new_all=""
    for entry in $VPN_REMOTE_MAP; do
        new_all="${new_all}
${entry#*=}"
    done
    new_all=$(printf '%s\n' "$new_all" | tr ',' '\n' | sort -u)
    for entry in $old_map; do
        host="${entry%%=*}"
        for ip in $(printf '%s\n' "${entry#*=}" | tr ',' '\n'); do
            printf '%s\n' "$new_all" | grep -qx "$ip" && continue
            for endpoint in ${VPN_REMOTE_IPS:-}; do
                rest="${endpoint#*|}"
                port="${rest%%|*}"
                proto="${rest#*|}"
                [ "${endpoint%%|*}" = "$ip" ] && [ -n "$port" ] && [ -n "$proto" ] || continue
                if [[ "$ip" =~ : ]]; then
                    ipt6 -D OUTPUT -o "$phys_iface" -d "$ip" -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
                else
                    iptables -D OUTPUT -o "$phys_iface" -d "$ip" -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
                fi
            done
            log_json INFO "vpn_remote_refresh" \
                "removed stale VPN remote rule" \
                "ip=${ip}"
        done
    done

    # 3. Regenerer VPN_REMOTE_IPS (endpoints "ip|port|proto") : pour chaque
    #    hostname de la nouvelle carte, les ports/protos sont ceux que le
    #    pare-feu autorisait pour les ANCIENNES IP du meme hostname. Un
    #    hostname dont les IP sont inchangees garde ses endpoints tels quels.
    local updated_eps="" ep_port ep_proto old_host old_ip_list ep_ip
    local -A host_eps=()
    for old_entry in $old_map; do
        old_host="${old_entry%%=*}"
        host_eps[$old_host]=""
        for endpoint in ${VPN_REMOTE_IPS:-}; do
            ep_ip="${endpoint%%|*}"
            printf '%s\n' "${old_entry#*=}" | tr ',' '\n' | grep -qx "$ep_ip" || continue
            rest="${endpoint#*|}"
            ep_port="${rest%%|*}"
            ep_proto="${rest#*|}"
            case " ${host_eps[$old_host]} " in
                *" ${ep_port}|${ep_proto}"*) ;;
                *) host_eps[$old_host]="${host_eps[$old_host]} ${ep_port}|${ep_proto}" ;;
            esac
        done
    done
    for entry in $VPN_REMOTE_MAP; do
        host="${entry%%=*}"
        for ip in $(printf '%s\n' "${entry#*=}" | tr ',' '\n'); do
            for pp in ${host_eps[$host]:-}; do
                updated_eps="${updated_eps} ${ip}|${pp}"
            done
        done
    done
    export VPN_REMOTE_IPS="${updated_eps# }"

    log_json INFO "vpn_remote_refresh" \
        "VPN remote refresh complete" \
        "map=${VPN_REMOTE_MAP}" \
        "endpoints=$(echo ${VPN_REMOTE_IPS:-} | wc -w)"
    return 1
}


setup_iptables() {
    log_json INFO "setup_iptables" "Configuring IPv4 firewall"

    local docker_network
    docker_network=$(
        ip -o addr show dev eth0 2>/dev/null |
            awk '$3=="inet"{print $4}' || true
    )

    get_vpn_port_proto "$VPN_CONF"

    iptables -F
    iptables -X
    iptables -t nat -F

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # DNS bootstrap : uniquement hors DoT. En mode DoT le port 53 externe
    # doit rester strictement bloque (anti-fuite, H5) : dnsmasq forward en
    # local vers unbound (5053).
    if [ "${ENABLE_DOT:-false}" != "true" ]; then
        local dns
        for dns in "$DNS_SERVER_1" "$DNS_SERVER_2"; do
            iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
        done
    fi

    # Healthcheck (ping sonde) - pas de port 53 externe : en mode DoT le
    # port 53 hors tunnel doit rester strictement bloque (H5).
    if [ "${ENABLE_DOT:-false}" != "true" ]; then
        iptables -A OUTPUT -p udp -d "$HEALTHCHECK_IP" --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "$HEALTHCHECK_IP" --dport 53 -j ACCEPT
    fi
    # Sonde de sante limitee a l'interface physique (reduit la brèche
    # residuelle vers un seul hote, toutes interfaces). Les sondes peuvent
    # aussi passer par le tunnel une fois celui-ci monte.
    local hc_iface
    hc_iface=$(get_physical_iface)
    hc_iface="${hc_iface:-eth0}"
    iptables -A OUTPUT -o "$hc_iface" -p tcp -d "$HEALTHCHECK_IP" --dport 80 -j ACCEPT
    iptables -A OUTPUT -o "$hc_iface" -p tcp -d "$HEALTHCHECK_IP" --dport 443 -j ACCEPT

    # INPUT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT

    if [ -n "$docker_network" ]; then
        iptables -A INPUT -s "$docker_network" -j ACCEPT
    fi

    # External proxy access (if explicitly enabled)
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        iptables -A INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        log_json INFO "setup_iptables" \
            "Proxy port open to external access" \
            "port=${PROXY_PORT}"
    else
        log_json INFO "setup_iptables" \
            "Proxy port restricted to Docker network only" \
            "port=${PROXY_PORT}"
    fi

    # FORWARD
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i lo -j ACCEPT

    if [ -n "$docker_network" ]; then
        iptables -A FORWARD -s "$docker_network" -j ACCEPT
        iptables -A FORWARD -d "$docker_network" -j ACCEPT
    fi

    iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o wg+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i tap+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i wg+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # OUTPUT - interfaces autorisées
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tun+ -j ACCEPT
    iptables -A OUTPUT -o tap+ -j ACCEPT
    iptables -A OUTPUT -o wg+ -j ACCEPT
    iptables -A OUTPUT -o tailscale+ -j ACCEPT

    if [ -n "$docker_network" ]; then
        iptables -A OUTPUT -d "$docker_network" -j ACCEPT
    fi

    # Proxy responses (allow replies back when external access enabled)
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        iptables -A OUTPUT -p tcp --sport "$PROXY_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        log_json INFO "setup_iptables" \
            "Proxy response traffic allowed via eth0" \
            "port=${PROXY_PORT}"
    fi

    # Métriques
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 9100 -j ACCEPT

    # DNS local
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 5053 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 5053 -j ACCEPT

    # DoT
    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        if [ -n "$DOT_RESOLVED_IPS" ]; then
            local dot_ip

            for dot_ip in $DOT_RESOLVED_IPS; do
                ipt_add_853 "$dot_ip"

                log_json INFO "setup_iptables" \
                    "DoT: allowing TCP 853" \
                    "ip=${dot_ip}"
            done
        else
            log_json WARN "setup_iptables" \
                "DoT: no resolved IPs - TCP 853 not explicitly allowed"
        fi

        # Kill switch DNS externe.
        iptables -A OUTPUT -p udp ! -d 127.0.0.0/8 --dport 53 -j DROP
        iptables -A OUTPUT -p tcp ! -d 127.0.0.0/8 --dport 53 -j DROP

        log_json INFO "setup_iptables" \
            "DoT DNS leak prevention: external port 53 blocked"
    else
        # Mode DNS classique.
        local _dns

        for _dns in "$DNS_SERVER_1" "$DNS_SERVER_2"; do
            [[ "$_dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue

            iptables -A OUTPUT -p udp -d "$_dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$_dns" --dport 53 -j ACCEPT

            log_json INFO "setup_iptables" \
                "allowing port 53" \
                "ip=${_dns}"
        done

        while read -r _dns; do
            [[ "$_dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue

            iptables -A OUTPUT -p udp -d "$_dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$_dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams "$DNSMASQ_CONF")
    fi

    # Retire la regle de bootstrap tcp/443 posee par firewall_early_lockdown
    # (les regles VPN ciblees et l'interface tun prennent le relais).
    iptables -D OUTPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true

    # DNS Docker interne.
    if grep -Fq "127.0.0.11" "$RESOLV_CONF" 2>/dev/null; then
        iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT
        iptables -A OUTPUT -p udp -d 127.0.0.11 --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d 127.0.0.11 --dport 53 -j ACCEPT
    fi

    # VPN Configuration - regles ciblees par remote (C2/R2/R6) : les IPs ont
    # ete resolues pendant le bootstrap (firewall_early_lockdown) et stockees
    # dans VPN_REMOTE_IPS sous la forme "ip|port|proto". Resoudre ici serait
    # trop tard en mode DoT (port 53 externe bloque). Pas de fallback par
    # port : si aucune regle n'est posee, on echoue ferme (fail-closed).
    local phys_iface
    phys_iface=$(get_physical_iface)
    phys_iface="${phys_iface:-eth0}"

    local endpoint rest r_ip r_port r_proto
    local rule_added=0
    for endpoint in ${VPN_REMOTE_IPS:-}; do
        rest="${endpoint#*|}"
        r_ip="${endpoint%%|*}"
        r_port="${rest%%|*}"
        r_proto="${rest#*|}"
        [ -n "$r_ip" ] && [ -n "$r_port" ] && [ -n "$r_proto" ] || continue

        if [[ "$r_ip" =~ : ]]; then
            if ipt6 -A OUTPUT -o "$phys_iface" -d "$r_ip" -p "$r_proto" --dport "$r_port" -j ACCEPT; then
                rule_added=$((rule_added + 1))
            else
                log_json ERROR "setup_iptables" \
                    "failed to add IPv6 VPN remote rule" \
                    "ip=${r_ip}" "proto=${r_proto}" "port=${r_port}"
            fi
        else
            if iptables -A OUTPUT -o "$phys_iface" -d "$r_ip" -p "$r_proto" --dport "$r_port" -j ACCEPT; then
                rule_added=$((rule_added + 1))
                log_json INFO "setup_iptables" \
                    "VPN remote allowed" \
                    "iface=${phys_iface}" "ip=${r_ip}" "proto=${r_proto}" "port=${r_port}"
            else
                log_json ERROR "setup_iptables" \
                    "failed to add VPN remote rule" \
                    "iface=${phys_iface}" "ip=${r_ip}" "proto=${r_proto}" "port=${r_port}"
            fi
        fi
    done

    if [ "$rule_added" -eq 0 ]; then
        log_json ERROR "setup_iptables" \
            "no VPN remote rule could be added - failing closed" \
            "endpoints=${VPN_REMOTE_IPS:-none}"
        FW_FAILED=1
        return 1
    fi

    if [ "${VPN_TYPE:-openvpn}" = "wireguard" ]; then
        iptables -A OUTPUT -o wg+ -j ACCEPT
        iptables -t nat -A POSTROUTING -o wg+ -j MASQUERADE
        log_json INFO "setup_iptables" "WireGuard firewall rules configured" \
            "remotes=${rule_added}"
    else
        iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
        iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE
        log_json INFO "setup_iptables" "OpenVPN firewall rules configured" \
            "vpn_proto=${VPN_PROTO}" \
            "vpn_port=${VPN_PORT}" \
            "remotes=${rule_added}"
    fi

    log_json INFO "setup_iptables" \
        "IPv4 configured - kill switch active" \
        "vpn_proto=${VPN_PROTO}" \
        "vpn_port=${VPN_PORT}"
}

# ===========================================================================
# IPv6 Firewall - Kill switch + DNS leak prevention
# ===========================================================================

setup_ip6tables() {
    log_json INFO "setup_ip6tables" "Configuring IPv6 firewall"

    if ! command_exists ip6tables; then
        log_json WARN "setup_ip6tables" \
            "ip6tables not installed, skipping"
        return 0
    fi

    if [ ! -f /proc/net/if_inet6 ]; then
        log_json WARN "setup_ip6tables" \
            "IPv6 not available, skipping"
        return 0
    fi

    local docker6_network
    local phys_iface_v6
    phys_iface_v6=$(get_physical_iface)
    phys_iface_v6="${phys_iface_v6:-eth0}"

    docker6_network=$(
        ip -o addr show dev eth0 2>/dev/null |
            awk '$3=="inet6"{print $4; exit}' || true
    )

    ipt6 -F
    ipt6 -X
    ipt6 -t nat -F

    ipt6 -P INPUT DROP
    ipt6 -P FORWARD DROP
    ipt6 -P OUTPUT DROP

    ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A INPUT -p icmpv6 -j ACCEPT
    ipt6 -A INPUT -i lo -j ACCEPT

    if [ -n "$docker6_network" ]; then
        ipt6 -A INPUT -s "$docker6_network" -j ACCEPT
    fi

    # External proxy access (if explicitly enabled)
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        ipt6 -A INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    fi

    ipt6 -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -p icmpv6 -j ACCEPT
    ipt6 -A FORWARD -i lo -j ACCEPT

    if [ -n "$docker6_network" ]; then
        ipt6 -A FORWARD -s "$docker6_network" -j ACCEPT
        ipt6 -A FORWARD -d "$docker6_network" -j ACCEPT
    fi

    ipt6 -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o wg+ -j ACCEPT
    ipt6 -A FORWARD -i tun+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i tap+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i wg+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A OUTPUT -o lo -j ACCEPT
    ipt6 -A OUTPUT -o tun+ -j ACCEPT
    ipt6 -A OUTPUT -o tap+ -j ACCEPT
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT
    ipt6 -A OUTPUT -o wg+ -j ACCEPT

    if [ -n "$docker6_network" ]; then
        ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT
    fi

    # Proxy responses (allow replies back when external access enabled)
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        ipt6 -A OUTPUT -p tcp --sport "$PROXY_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi

    ipt6 -A OUTPUT -p tcp -d ::1 --dport 9100 -j ACCEPT

    ipt6 -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p udp -d ::1 --dport 5053 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 5053 -j ACCEPT

    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        ipt6 -A OUTPUT -p udp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true
        ipt6 -A OUTPUT -p tcp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true

        log_json INFO "setup_ip6tables" \
            "DoT DNS leak prevention: IPv6 port 53 blocked"
    else
        while read -r dns; do
            [[ "$dns" =~ : ]] || continue

            ipt6 -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            ipt6 -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams "$DNSMASQ_CONF")
    fi

    # B4 : les regles IPv6 des remotes ont ete posees par setup_iptables
    # (boucle VPN_REMOTE_IPS) MAIS le "ipt6 -F" en tete de cette fonction
    # les efface. Re-poser les endpoints IPv6 depuis la liste pre-resolue.
    local endpoint rest6 r6_ip r6_port r6_proto
    for endpoint in ${VPN_REMOTE_IPS:-}; do
        rest6="${endpoint#*|}"
        r6_ip="${endpoint%%|*}"
        r6_port="${rest6%%|*}"
        r6_proto="${rest6#*|}"
        [[ "$r6_ip" =~ : ]] || continue
        ipt6 -A OUTPUT -o "$phys_iface_v6" -d "$r6_ip" -p "$r6_proto" --dport "$r6_port" -j ACCEPT
    done

    ipt6 -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    ipt6 -t nat -A POSTROUTING -o tap+ -j MASQUERADE
    ipt6 -t nat -A POSTROUTING -o wg+ -j MASQUERADE

    log_json INFO "setup_ip6tables" \
        "IPv6 configured - kill switch active"
}

# ===========================================================================
# Advanced proxy routing - force proxy responses via physical interface
# ===========================================================================

setup_proxy_routing() {
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" != "true" ]; then
        log_json INFO "setup_proxy_routing" \
            "Skipped - ALLOW_EXTERNAL_PROXY_ACCESS is not true"
        return 0
    fi

    log_json INFO "setup_proxy_routing" \
        "Configuring proxy routing to force responses via physical interface"

    # Track proxy client connections in conntrack and mark response packets.
    # Using CONNMARK is more reliable than only matching source port in OUTPUT.
    if ! iptables -t mangle -C PREROUTING -p tcp --dport "$PROXY_PORT" -j CONNMARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A PREROUTING -p tcp --dport "$PROXY_PORT" -j CONNMARK --set-mark 0x1
    fi

    # Restore packet mark from connection mark for locally generated responses.
    if ! iptables -t mangle -C OUTPUT -m connmark --mark 0x1 -j MARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A OUTPUT -m connmark --mark 0x1 -j MARK --set-mark 0x1
    fi

    # Fallback: directly mark packets emitted from proxy port.
    if ! iptables -t mangle -C OUTPUT -p tcp --sport "$PROXY_PORT" -j MARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A OUTPUT -p tcp --sport "$PROXY_PORT" -j MARK --set-mark 0x1
    fi

    # Create a new routing table for marked traffic
    # Use table 100 (avoid conflicts with default tables 0-252)
    # Ensure the rt_tables directory and file exist
    mkdir -p /etc/iproute2
    touch /etc/iproute2/rt_tables
    
    if ! grep -q "^100" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "100 proxy_rt" >> /etc/iproute2/rt_tables 2>/dev/null || true
    fi

    # Get the main gateway and interface (usually eth0)
    local main_gateway
    local main_iface
    main_gateway=$(ip route show | grep "^default" | grep -v "tun\|tap\|wg" | awk '{print $3}' | head -1)
    main_iface=$(ip route show | grep "^default" | grep -v "tun\|tap\|wg" | awk '{print $5}' | head -1)

    if [ -z "$main_gateway" ] || [ -z "$main_iface" ]; then
        log_json WARN "setup_proxy_routing" \
            "Could not determine main gateway or interface - skipping advanced routing"
        return 0
    fi

    # Keep proxy routing table in sync with current gateway/interface.
    ip route replace default via "$main_gateway" dev "$main_iface" table 100 2>/dev/null || true

    # Route marked packets via proxy routing table with high priority
    # so it wins over source-based rules (e.g. table 10).
    if ! ip rule show | grep -q "pref 100 .*fwmark 0x1 .*lookup proxy_rt\|pref 100 .*fwmark 0x1 .*lookup 100"; then
        ip rule add pref 100 fwmark 0x1 lookup 100 2>/dev/null || true
    fi

    log_json INFO "setup_proxy_routing" \
        "Proxy routing configured - connmark + fwmark policy active" \
        "gateway=${main_gateway}" \
        "interface=${main_iface}" \
        "mark=0x1" \
        "table=100"
}

# ===========================================================================
# Return routes configuration
# ===========================================================================

setup_return_routes() {
    log_json INFO "setup_return_routes" "Configuring return routes"

    local iface gw gw6 ips ip6s ip

    iface=$(
        ip route 2>/dev/null |
            awk '/^default/{print $5; exit}'
    )

    if [ -z "$iface" ]; then
        log_json WARN "setup_return_routes" \
            "no default interface found, skipping"
        return 0
    fi

    gw=$(
        ip -4 route show dev "$iface" 2>/dev/null |
            awk '/default/{print $3; exit}'
    )

    gw6=$(
        ip -6 route show dev "$iface" 2>/dev/null |
            awk '/default/{print $3; exit}'
    )

    ips=$(
        ip -4 addr show dev "$iface" 2>/dev/null |
            awk -F'[ /]+' '/inet /{print $3}'
    )

    ip6s=$(
        ip -6 addr show dev "$iface" 2>/dev/null |
            awk -F'[ /]+' '/inet6.*global/{print $3}'
    )

    for ip in $ips; do
        if ! ip -4 rule show table 10 2>/dev/null | grep -q "$ip"; then
            ip rule add from "$ip" lookup 10 2>/dev/null || true
        fi

        # NB : pas de "iptables -A INPUT -d $ip -j ACCEPT" : cette regle
        # acceptait TOUT paquet adresse au conteneur depuis n'importe quelle
        # source, annulant INPUT DROP et ALLOW_EXTERNAL_PROXY_ACCESS. Les
        # paquets legitimes (conntrack ESTABLISHED,RELATED) passent deja.
    done

    if [ -n "$gw" ]; then
        if ! ip -4 route show table 10 2>/dev/null | grep -q "default"; then
            ip route add default via "$gw" table 10 2>/dev/null || true
        fi
    fi

    local ip6
    for ip6 in $ip6s; do
        if ! ip -6 rule show table 10 2>/dev/null | grep -q "$ip6"; then
            ip -6 rule add from "$ip6" lookup 10 2>/dev/null || true
        fi
        # Pas de regle INPUT -d $ip6 ACCEPT (voir boucle IPv4 ci-dessus).
    done

    if [ -n "$gw6" ]; then
        if ! ip -6 route show table 10 2>/dev/null | grep -q "default"; then
            ip -6 route add default via "$gw6" table 10 2>/dev/null || true
        fi
    fi

    log_json INFO "setup_return_routes" \
        "return routes configured" \
        "iface=${iface}"
}

# ===========================================================================
# Cleanup routes on restart
# ===========================================================================

cleanup_routes_on_restart() {
    local tun_dev

    tun_dev=$(find_vpn_interface || true)

    if [ -n "$tun_dev" ] &&
        ip link show "$tun_dev" >/dev/null 2>&1; then

        log_json DEBUG "supervisor" \
            "cleaning up TUN device" \
            "dev=$tun_dev"

        timeout 3 ip addr flush dev "$tun_dev" 2>/dev/null || true
    fi

    timeout 3 ip route del default via 0.0.0.0 2>/dev/null || true
    timeout 3 ip route del 0.0.0.0/1 via 10.0.0.0 2>/dev/null || true
    # Clean up WireGuard routes
    timeout 3 ip route del 0.0.0.0/1 dev wg0 2>/dev/null || true
    timeout 3 ip route del 128.0.0.0/1 dev wg0 2>/dev/null || true
}
