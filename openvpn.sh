#!/bin/bash

# ===========================================================================
# openvpn.sh - Script de lancement d'OpenVPN
# 
# Ce script lance OpenVPN avec la configuration spécifiée.
# Il est conçu pour être appelé par le superviseur principal (start.sh).
# 
# Auteur: Vibe Code (amélioration 2026)
# Licence: MIT
# Version: 2.0.0
# ===========================================================================

set -euo pipefail

# Charger les fonctions communes
#SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#source "${SCRIPT_DIR}/lib/common.sh"
source "/usr/local/lib/common.sh"

# Initialiser l'environnement
init_environment

# ===========================================================================
# Configuration
# ===========================================================================

# Dossier et fichier de configuration OpenVPN
dir="${DEFAULT_VPN_DIR}"
conf="${dir}/vpn.conf"

# Vérifier que le fichier de configuration existe
if [ ! -f "$conf" ]; then
    log_json ERROR "openvpn.sh" \
        "Configuration file not found" \
        "expected=${conf}"
    exit 1
fi

# Vérifier que le dossier existe
if [ ! -d "$dir" ]; then
    log_json ERROR "openvpn.sh" \
        "Configuration directory not found" \
        "expected=${dir}"
    exit 1
fi

# Vérifier que OpenVPN est installé
if ! command_exists openvpn; then
    log_json ERROR "openvpn.sh" "openvpn command not found"
    exit 1
fi

# ===========================================================================
# Exécution
# ===========================================================================

log_json INFO "openvpn.sh" \
    "Starting OpenVPN" \
    "config=${conf}" \
    "dir=${dir}"

exec openvpn --cd "$dir" --config "$conf"
