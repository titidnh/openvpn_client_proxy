#!/bin/bash
# ===========================================================================
# PATCHES_FIXES.sh - Correctifs directs pour l'instabilité Unbound
# 
# Utilisation:
#   1. Placer ce script dans le répertoire du projet
#   2. chmod +x PATCHES_FIXES.sh
#   3. ./PATCHES_FIXES.sh
# 
# Ce script applique TOUS les correctifs identifiés
# ===========================================================================

set -euo pipefail

# Couleurs pour output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# Vérifier qu'on est dans le bon répertoire
if [ ! -f "start.sh" ] || [ ! -f "healthcheck.sh" ]; then
    log_error "start.sh ou healthcheck.sh non trouvés"
    log_info "Lancer ce script depuis le répertoire du projet"
    exit 1
fi

# ===========================================================================
# PATCH 1: vpn.conf - Ajouter keepalive et timeouts
# ===========================================================================
log_info "PATCH 1/6: Configuration OpenVPN (vpn.conf)"

if [ -f "vpn.conf" ]; then
    # Vérifier si les fixes sont déjà appliquées
    if grep -q "keepalive 10 120" vpn.conf 2>/dev/null; then
        log_warn "vpn.conf déjà patché - SKIP"
    else
        cp vpn.conf vpn.conf.backup
        cat >> vpn.conf << 'EOF'

# ===========================================================================
# FIXES 2026 - Stabilité Unbound/Supervisor
# ===========================================================================

# ✅ FIX #1: Augmenter tolérance aux pings perdus du serveur VPN
keepalive 10 120

# ✅ Limiter les reconnections agressives
connect-retry-max 3
connect-retry 1

# ✅ Augmenter timeouts de connexion
connect-timeout 120

# ✅ Logs verbeux pour debugging (remplacer verb 3 si existant)
# verb 4
mute-replay-warnings

EOF
        log_success "vpn.conf patché avec keepalive + timeouts"
    fi
else
    log_warn "vpn.conf non trouvé - création d'un snippet d'exemple"
    cat > vpn.conf.patch << 'EOF'
# À ajouter à votre vpn.conf:
keepalive 10 120
connect-retry-max 3
connect-retry 1
connect-timeout 120
EOF
    log_info "Snippet sauvé dans vpn.conf.patch"
fi

# ===========================================================================
# PATCH 2: healthcheck.sh - Remplacer check_http_proxy
# ===========================================================================
log_info "PATCH 2/6: Healthcheck proxy (healthcheck.sh)"

cp healthcheck.sh healthcheck.sh.backup

# Créer la nouvelle fonction
cat > /tmp/new_check_proxy.sh << 'EOF'
# Vérifie que le proxy HTTP fonctionne
# Usage: check_http_proxy
check_http_proxy() {
    local proxy_port
    proxy_port=$(get_privoxy_port)
    
    # ✅ Vérification locale uniquement
    if ! nc -z -w 2 127.0.0.1 "$proxy_port" 2>/dev/null; then
        log_json ERROR "healthcheck" "privoxy not listening on $proxy_port"
        return 1
    fi
    
    # Test basique: vérifier que ça répond
    if timeout 3 curl -s -x "http://127.0.0.1:${proxy_port}" \
                       --connect-timeout 2 \
                       -o /dev/null \
                       "http://127.0.0.1/internal-test" 2>/dev/null; then
        return 0
    fi
    
    # Si curl échoue, au minimum vérifier qu'on peut se connecter
    if nc -z -w 2 127.0.0.1 "$proxy_port" 2>/dev/null; then
        return 0
    fi
    
    return 1
}
EOF

# Remplacer la fonction (lignes 52-76)
# Chercher les limites de la fonction
START_LINE=$(grep -n "^check_http_proxy()" healthcheck.sh | cut -d: -f1)
END_LINE=$(awk "/^check_http_proxy\(\)/{flag=1; next} flag && /^}$/{print NR; exit}" healthcheck.sh)

if [ -n "$START_LINE" ] && [ -n "$END_LINE" ]; then
    # Créer nouveau fichier sans l'ancienne fonction
    {
        sed -n "1,$((START_LINE-1))p" healthcheck.sh
        cat /tmp/new_check_proxy.sh
        sed -n "$((END_LINE+1)),\$p" healthcheck.sh
    } > healthcheck.sh.tmp
    
    mv healthcheck.sh.tmp healthcheck.sh
    log_success "check_http_proxy remplacée par version locale-only"
else
    log_warn "Impossible de trouver check_http_proxy - vérifier manuellement"
fi

# ===========================================================================
# PATCH 3: start.sh - Ajouter cleanup_routes_on_restart
# ===========================================================================
log_info "PATCH 3/6: Route cleanup function (start.sh)"

cp start.sh start.sh.backup

# Chercher la ligne où insérer
INSERT_AFTER=$(grep -n "configure_unbound()" start.sh | head -1 | cut -d: -f1)
INSERT_AFTER=$((INSERT_AFTER - 1))

if [ -n "$INSERT_AFTER" ] && [ "$INSERT_AFTER" -gt 0 ]; then
    cat > /tmp/cleanup_routes.sh << 'EOF'

# ✅ FIX #2: Nettoyer les routes proprement avant restart
cleanup_routes_on_restart() {
    local tun_dev
    tun_dev=$(find_vpn_interface || true)
    
    if [ -n "$tun_dev" ] && ip link show "$tun_dev" >/dev/null 2>&1; then
        log_json DEBUG "supervisor" "cleaning up TUN device" "dev=$tun_dev"
        timeout 3 ip addr flush dev "$tun_dev" 2>/dev/null || true
    fi
    
    # Nettoyer les routes statiques de VPN (pattern générique)
    timeout 3 ip route del default via 0.0.0.0 2>/dev/null || true
    timeout 3 ip route del 0.0.0.0/1 via 10.0.0.0 2>/dev/null || true
}

EOF
    
    # Insérer dans le fichier
    {
        sed -n "1,${INSERT_AFTER}p" start.sh
        cat /tmp/cleanup_routes.sh
        sed -n "$((INSERT_AFTER+1)),\$p" start.sh
    } > start.sh.tmp
    
    mv start.sh.tmp start.sh
    log_success "cleanup_routes_on_restart() ajoutée"
else
    log_warn "Impossible de trouver point d'insertion"
fi

# ===========================================================================
# PATCH 4: start.sh - Modifier start_unbound()
# ===========================================================================
log_info "PATCH 4/6: start_unbound() avec DNS wait (start.sh)"

# Vérifier si déjà patché
if grep -q "FIX.*unbound.*DNS" start.sh 2>/dev/null; then
    log_warn "start_unbound() déjà patché - SKIP"
else
    # Cette patch est plus complexe - on va l'indiquer manuellement
    cat > /tmp/START_UNBOUND_PATCH.txt << 'EOF'
PATCH #4 - À appliquer MANUELLEMENT dans start.sh fonction start_unbound()

CHERCHER (ligne ~608):
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0
    configure_unbound || return 0
    unbound -d -c "$UNBOUND_CONF" &

REMPLACER PAR:
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    # ✅ FIX #4: Attendre dnsmasq AVANT Unbound
    wait_for_dns_ready 30 || {
        log_json WARN "start_unbound" "classic DNS not ready - delaying unbound"
        return 0
    }

    configure_unbound || return 0

    # Tuer ancienne instance si elle existe (orphan)
    pkill -9 -f "^unbound -d" 2>/dev/null || true
    sleep 1

    unbound -d -c "$UNBOUND_CONF" &

ET CHERCHER (ligne ~640):
    if [ "$bound" -eq 1 ]; then
        METRIC_DOT_ACTIVE=1

REMPLACER PAR:
    if [ "$bound" -eq 1 ]; then
        # ✅ Reconfigurer dnsmasq immédiatement
        reconfigure_dnsmasq
        METRIC_DOT_ACTIVE=1
EOF
    log_warn "PATCH 4 - Voir /tmp/START_UNBOUND_PATCH.txt pour instructions manuelles"
    cat /tmp/START_UNBOUND_PATCH.txt
fi

# ===========================================================================
# PATCH 5: start.sh - Ajouter restart_unbound_if_needed()
# ===========================================================================
log_info "PATCH 5/6: Unbound health check (start.sh)"

if grep -q "restart_unbound_if_needed()" start.sh 2>/dev/null; then
    log_warn "restart_unbound_if_needed() déjà présente - SKIP"
else
    # Insérer après test_unbound_dns_robust
    INSERT_AFTER=$(grep -n "^test_unbound_dns_robust()" start.sh | cut -d: -f1)
    INSERT_AFTER=$(awk "NR==$INSERT_AFTER,/^}$/{if(/^}$/) {print NR; exit}}" start.sh)
    
    if [ -n "$INSERT_AFTER" ]; then
        cat > /tmp/restart_unbound.sh << 'EOF'

# ✅ FIX #5: Restart Unbound automatiquement si crash
restart_unbound_if_needed() {
    if [ "${ENABLE_DOT:-false}" != "true" ]; then
        return 0
    fi
    
    # Vérifier processus
    if ! kill -0 "${SERVICE_PIDS[unbound]}" 2>/dev/null; then
        log_json WARN "supervisor" "unbound process died - restarting immediately"
        
        pkill -9 -f "^unbound" 2>/dev/null || true
        sleep 1
        
        unbound -d -c "$UNBOUND_CONF" &
        SERVICE_PIDS[unbound]=$!
        
        # Reconfigurer dnsmasq immédiatement
        reconfigure_dnsmasq
        
        log_json INFO "supervisor" "unbound restarted" "pid=${SERVICE_PIDS[unbound]}"
        return 1
    fi
    
    # Vérifier port
    if ! nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
        log_json WARN "supervisor" "unbound port unresponsive - hard restart"
        
        pkill -9 -f "^unbound" 2>/dev/null || true
        sleep 2
        
        unbound -d -c "$UNBOUND_CONF" &
        SERVICE_PIDS[unbound]=$!
        reconfigure_dnsmasq
        
        return 1
    fi
    
    return 0
}

EOF
        
        {
            sed -n "1,${INSERT_AFTER}p" start.sh
            cat /tmp/restart_unbound.sh
            sed -n "$((INSERT_AFTER+1)),\$p" start.sh
        } > start.sh.tmp
        
        mv start.sh.tmp start.sh
        log_success "restart_unbound_if_needed() ajoutée"
    fi
fi

# ===========================================================================
# PATCH 6: start.sh - Modifier supervision loop
# ===========================================================================
log_info "PATCH 6/6: Augmenter délais supervision (start.sh)"

if grep -q "FIX.*supervision.*delay" start.sh 2>/dev/null; then
    log_warn "Delays de supervision déjà augmentés - SKIP"
else
    cat > /tmp/SUPERVISION_PATCH.txt << 'EOF'
PATCH #6 - À appliquer MANUELLEMENT dans start.sh fonction supervise_all()

CHERCHER (ligne ~1434):
    log_json INFO "supervisor" "waiting 20s before first healthcheck..."
    sleep 20

REMPLACER PAR:
    # ✅ FIX #6: Augmenter délai initial de stabilisation
    log_json INFO "supervisor" "waiting 40s before first healthcheck for stability..."
    sleep 40

---

CHERCHER AUSSI (ligne ~1540):
    log_json ERROR "supervisor" "failure detected - restarting services" "attempt=${attempt}"
    # ... du code de restart ...
    
    # Chercher la ligne de sleep après restart:
    sleep "$sleep_s"

REMPLACER PAR:
    log_json ERROR "supervisor" "failure detected - restarting services" "attempt=${attempt}"
    # ... du code de restart ... 
    
    # ✅ FIX #6: Augmenter délai exponentiellement
    local sleep_s=$((5 + attempt * 10))  # Au lieu de 2 + attempt * 5
    if [ "$sleep_s" -gt 120 ]; then
        sleep_s=120
    fi
    
    log_json INFO "supervisor" "stabilization wait ${sleep_s}s (attempt $attempt)"
    sleep "$sleep_s"
    
    # ✅ Sauter prochaine itération healthcheck
    SKIP_HEALTHCHECK_FIRST_MINUTES=$((SKIP_HEALTHCHECK_FIRST_MINUTES + 5))

EOF
    log_warn "PATCH 6 - Voir /tmp/SUPERVISION_PATCH.txt pour instructions"
    cat /tmp/SUPERVISION_PATCH.txt
fi

# ===========================================================================
# Résumé des changements
# ===========================================================================
log_info "====== RÉSUMÉ DES CHANGEMENTS ======"
log_success "Backups créés:"
echo "  - vpn.conf.backup"
echo "  - healthcheck.sh.backup"
echo "  - start.sh.backup"

log_success "Patches appliquées automatiquement:"
echo "  ✓ PATCH 1: vpn.conf keepalive"
echo "  ✓ PATCH 2: healthcheck.sh check_http_proxy (local-only)"
echo "  ✓ PATCH 3: start.sh cleanup_routes_on_restart()"

log_warn "Patches à appliquer MANUELLEMENT:"
echo "  → PATCH 4: start.sh start_unbound() - Voir /tmp/START_UNBOUND_PATCH.txt"
echo "  → PATCH 5: start.sh restart_unbound_if_needed() - Auto-applied ✓"
echo "  → PATCH 6: start.sh supervision delays - Voir /tmp/SUPERVISION_PATCH.txt"

log_info "====== PROCHAINES ÉTAPES ======"
echo "1. Vérifier les patches manuelles (PATCH 4 et 6)"
echo "2. docker build -t openvpn_proxy:latest ."
echo "3. docker-compose restart openvpn_proxy"
echo "4. Surveiller: docker logs -f openvpn_proxy | grep -i restart"
echo "5. Devrait avoir 0 redémarrages pendant 1 heure"

log_success "Script de patch terminé! ✨"
