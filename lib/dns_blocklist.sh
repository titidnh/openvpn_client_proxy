#!/bin/bash
#
# dns_blocklist.sh - DNS Blocklist management module
# 
# Downloads, compiles, and manages DNS blocklists for dnsmasq/unbound
# Supports multiple formats: hosts, adblock, raw domain lists
#
# Licensed under the same terms as the main project
#

# Source common utilities
# shellcheck source=/dev/null
source "/usr/local/lib/common.sh"

download_blocklists() {
    [ "${ENABLE_DNS_BLOCKLIST:-false}" = "true" ] || return 0

    mkdir -p "$DNS_BLOCKLIST_RAW_DIR"

    # Anti rafale : ne pas re-télécharger à chaque retry interne du
    # superviseur (mêmes causes que le problème DoT). On ne retélécharge
    # que si le cache est plus vieux que DNS_BLOCKLIST_MIN_AGE, sauf appel
    # forcé (refresh périodique qui supprime le fichier d'état avant).
    local min_age="${DNS_BLOCKLIST_MIN_AGE:-3600}"

    if [ -f "$DNS_BLOCKLIST_STATE_FILE" ]; then
        local last now age
        last=$(cat "$DNS_BLOCKLIST_STATE_FILE" 2>/dev/null || echo 0)
        now=$(date +%s)
        age=$((now - last))

        if [ "$age" -lt "$min_age" ]; then
            log_json INFO "dns_blocklist" \
                "cache encore frais - téléchargement ignoré" \
                "age=${age}s" "min_age=${min_age}s"
            return 0
        fi
    fi

    if ! command_exists curl; then
        log_json WARN "dns_blocklist" "curl indisponible - blocklist désactivée"
        return 1
    fi

    local urls
    urls=$(echo "${DNS_BLOCKLIST_URLS:-}" | tr ',' ' ')

    local ok=0
    local idx=0
    local url

    for url in $urls; do
        idx=$((idx + 1))

        local dest="${DNS_BLOCKLIST_RAW_DIR}/list_${idx}.txt"
        local tmp
        tmp=$(temp_file "blocklist_dl")

        if curl -fsSL --max-time 30 --retry 2 --retry-delay 2 \
            "$url" -o "$tmp" 2>/dev/null && [ -s "$tmp" ]; then

            mv -f "$tmp" "$dest"
            ok=$((ok + 1))

            log_json INFO "dns_blocklist" \
                "liste téléchargée" \
                "url=${url}" \
                "bytes=$(wc -c < "$dest" 2>/dev/null || echo 0)"
        else
            rm -f "$tmp"

            log_json WARN "dns_blocklist" \
                "échec téléchargement - conservation de la copie précédente si présente" \
                "url=${url}"
        fi
    done

    if [ "$ok" -eq 0 ]; then
        # Aucune source n'a répondu cette fois : si on a déjà des fichiers
        # en cache d'une exécution précédente, on continue avec eux.
        if ls "${DNS_BLOCKLIST_RAW_DIR}"/*.txt >/dev/null 2>&1; then
            log_json WARN "dns_blocklist" \
                "toutes les sources ont échoué - réutilisation du cache existant"
            return 0
        fi

        log_json ERROR "dns_blocklist" \
            "aucune liste disponible (échec + pas de cache) - blocklist inactive"
        return 1
    fi

    date +%s > "$DNS_BLOCKLIST_STATE_FILE"

    return 0
}

compile_blocklists() {
    [ "${ENABLE_DNS_BLOCKLIST:-false}" = "true" ] || return 0

    if ! ls "${DNS_BLOCKLIST_RAW_DIR}"/*.txt >/dev/null 2>&1; then
        log_json WARN "dns_blocklist" "aucun fichier source à compiler"
        return 1
    fi

    local tmp_all
    tmp_all=$(temp_file "blocklist_all")

    local f
    for f in "${DNS_BLOCKLIST_RAW_DIR}"/*.txt; do
        [ -f "$f" ] || continue

        # Format hosts : "0.0.0.0 domaine" ou "127.0.0.1 domaine"
        grep -E '^[[:space:]]*(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]+[a-zA-Z0-9]' \
            "$f" 2>/dev/null | awk '{print $2}' >> "$tmp_all" || true

        # Format Adblock/uBlock : "||domaine^"
        grep -oE '\|\|[a-zA-Z0-9.-]+\^' \
            "$f" 2>/dev/null | sed 's/^||//; s/\^$//' >> "$tmp_all" || true

        # Format liste brute : un domaine par ligne, sans commentaire
        grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[[:space:]]*$' \
            "$f" 2>/dev/null | awk '{print $1}' >> "$tmp_all" || true
    done

    # Normalisation : minuscules, tri, dédoublonnage, format de domaine valide
    local tmp_clean
    tmp_clean=$(temp_file "blocklist_clean")

    tr 'A-Z' 'a-z' < "$tmp_all" |
        sort -u |
        grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
        > "$tmp_clean" || true

    rm -f "$tmp_all"

    # Exclusions de sécurité : domaines locaux/réservés/infra jamais bloqués
    local tmp_filtered
    tmp_filtered=$(temp_file "blocklist_filtered")

    grep -vE '^(localhost|localhost\.localdomain|local|broadcasthost|ip6-[a-z]+|.*\.arpa|.*\.internal)$' \
        "$tmp_clean" > "$tmp_filtered" || true

    rm -f "$tmp_clean"

    # Liste blanche utilisateur (DNS_BLOCKLIST_ALLOWLIST) - garde-fou faux positifs
    local tmp_final
    tmp_final=$(temp_file "blocklist_final")

    if [ -n "${DNS_BLOCKLIST_ALLOWLIST:-}" ]; then
        local allow_pattern
        allow_pattern=$(echo "${DNS_BLOCKLIST_ALLOWLIST}" |
            tr ',' '|' |
            sed 's/\./\\./g')

        grep -vE "(^|\\.)(${allow_pattern})\$" \
            "$tmp_filtered" > "$tmp_final" || true
    else
        mv -f "$tmp_filtered" "$tmp_final"
    fi

    rm -f "$tmp_filtered" 2>/dev/null || true

    local total
    total=$(wc -l < "$tmp_final" 2>/dev/null || echo 0)

    # Garde-fou : une liste anormalement petite signale probablement un
    # problème de parsing (format inconnu) plutôt qu'une vraie liste vide.
    # On préfère garder l'ancienne compilation valide plutôt que de casser
    # la résolution DNS avec une liste quasi-vide.
    if [ "$total" -lt 100 ]; then
        log_json WARN "dns_blocklist" \
            "liste compilée anormalement petite - conservation de la version précédente" \
            "count=${total}"

        rm -f "$tmp_final"
        return 1
    fi

    # --- Fragment dnsmasq ---
    local tmp_dnsmasq
    tmp_dnsmasq=$(temp_file "blocklist_dnsmasq")

    awk '{
        print "address=/" $0 "/0.0.0.0"
        print "address=/" $0 "/::"
    }' "$tmp_final" > "$tmp_dnsmasq"

    mv -f "$tmp_dnsmasq" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    chmod 0644 "$DNS_BLOCKLIST_COMPILED_DNSMASQ" 2>/dev/null || true

    # --- Fragment unbound ---
    mkdir -p "$(dirname "$DNS_BLOCKLIST_COMPILED_UNBOUND")"

    local tmp_unbound
    tmp_unbound=$(temp_file "blocklist_unbound")

    awk '{ print "local-zone: \"" $0 ".\" always_nxdomain" }' \
        "$tmp_final" > "$tmp_unbound"

    mv -f "$tmp_unbound" "$DNS_BLOCKLIST_COMPILED_UNBOUND"
    chmod 0644 "$DNS_BLOCKLIST_COMPILED_UNBOUND" 2>/dev/null || true
    chown unbound:unbound "$DNS_BLOCKLIST_COMPILED_UNBOUND" 2>/dev/null || true

    rm -f "$tmp_final"

    log_json INFO "dns_blocklist" \
        "blocklist compilée" \
        "domaines=${total}"

    return 0
}

_blocklist_refresh_loop() {
    local interval="${DNS_BLOCKLIST_REFRESH_INTERVAL:-86400}"

    log_json INFO "dns_blocklist" \
        "démarrage du rafraîchissement périodique" \
        "interval=${interval}s"

    while true; do
        sleep "$interval"

        local before_hash after_hash
        before_hash=$(md5sum "$DNS_BLOCKLIST_COMPILED_DNSMASQ" 2>/dev/null | awk '{print $1}')

        # Forcer un vrai re-téléchargement (on ignore le cache d'âge minimal
        # ici puisque c'est justement le rafraîchissement programmé).
        rm -f "$DNS_BLOCKLIST_STATE_FILE"

        if ! download_blocklists; then
            log_json WARN "dns_blocklist" \
                "rafraîchissement périodique : téléchargement échoué, liste actuelle conservée"
            continue
        fi

        if ! compile_blocklists; then
            log_json WARN "dns_blocklist" \
                "rafraîchissement périodique : compilation échouée, liste actuelle conservée"
            continue
        fi

        after_hash=$(md5sum "$DNS_BLOCKLIST_COMPILED_DNSMASQ" 2>/dev/null | awk '{print $1}')

        if [ "$before_hash" = "$after_hash" ]; then
            log_json INFO "dns_blocklist" \
                "rafraîchissement périodique : aucun changement"
            continue
        fi

        log_json INFO "dns_blocklist" \
            "blocklist modifiée - rechargement du service DNS"

        if [ "${ENABLE_DOT:-false}" = "true" ]; then
            # unbound relit tout son fichier de config (dont les "include:")
            # sur un SIGHUP, pas besoin de le redémarrer.
            local ub_pid
            ub_pid=$(pidof unbound | awk '{print $1}' || true)

            if [ -n "$ub_pid" ]; then
                kill -HUP "$ub_pid" 2>/dev/null || true

                log_json INFO "dns_blocklist" \
                    "unbound rechargé (nouvelle blocklist)" \
                    "pid=${ub_pid}"
            fi
        else
            # ATTENTION : cette boucle tourne dans un sous-shell. Toute
            # ecriture dans SERVICE_PIDS serait perdue cote superviseur, qui
            # garderait un PID perime et redemarrerait TOUTE la pile (C8).
            # On relance dnsmasq via pidof ici, sans toucher SERVICE_PIDS :
            # le superviseur detectera le nouveau processus par le port/DNS.
            local dn_pid
            dn_pid=$(pidof dnsmasq | awk '{print $1}' || true)
            if [ -n "$dn_pid" ]; then
                kill "$dn_pid" 2>/dev/null || true
                sleep 1
            fi
            dnsmasq --no-daemon --conf-file="$DNSMASQ_CONF" --log-facility=- \
                >/dev/null 2>&1 &
            log_json INFO "dns_blocklist" \
                "dnsmasq relancé (nouvelle blocklist)" \
                "pid=$!"
        fi
    done
}

start_blocklist_refresh() {
    [ "${ENABLE_DNS_BLOCKLIST:-false}" = "true" ] || return 0

    _blocklist_refresh_loop &

    SERVICE_PIDS[blocklist_refresh]=$!

    log_json INFO "dns_blocklist" \
        "boucle de rafraîchissement démarrée" \
        "pid=${SERVICE_PIDS[blocklist_refresh]}"
}
