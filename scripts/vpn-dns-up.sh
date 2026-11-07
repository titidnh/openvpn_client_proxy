#!/bin/bash

# ===========================================================================
# vpn-dns-up.sh - Hook OpenVPN (--up / --route-up) pour DNS_FROM_VPN
#
# Extrait les serveurs DNS poussés par le serveur VPN (variables
# foreign_option_<n> : "dhcp-option DNS <ip>") et les écrit dans
# $VPN_PUSHED_DNS_FILE, une IP par ligne, pour que le superviseur bascule
# dnsmasq dessus (apply_vpn_pushed_dns, lib/dns_runtime.sh).
#
# Deux contextes d'exécution :
#   - --up       : en root, AVANT le drop de privilèges (--user vpn)
#   - --route-up : en utilisateur vpn, APRÈS le drop. Les reconnexions
#                  SIGUSR1 avec --persist-tun rejouent --route-up mais PAS
#                  --up : start_openvpn_local (scripts/start.sh) pré-créé
#                  donc le fichier cible appartenant à vpn:vpn (mode 664),
#                  inscriptible dans les deux contextes.
#
# Un serveur qui ne pousse aucun dhcp-option DNS ne modifie pas le fichier
# (le superviseur garde DNS_SERVER_1/2 en upstream de repli).
#
# Auteur: Vibe Code (amélioration 2026)
# Licence: MIT
# ===========================================================================

# Pas de set -e : une option poussée mal formée ne doit pas faire échouer le
# hook (OpenVPN traiterait un code de retour non nul comme une erreur fatale).
set -uo pipefail

file="${VPN_PUSHED_DNS_FILE:-/run/vpn-pushed-dns}"

# Sélection des "dhcp-option DNS <ip>". Les "dhcp-option DOMAIN ..." sont
# ignorées. foreign_option_1..n sont contiguës : on s'arrête à la première
# absente (garde-fou : 100 options maximum).
servers=""
count=0
idx=1
while [ "$idx" -le 100 ]; do
    opt="foreign_option_${idx}"
    opt_val="${!opt:-}"
    [ -n "$opt_val" ] || break

    if [[ "$opt_val" =~ ^dhcp-option[[:space:]]+DNS[[:space:]]+([^[:space:]]+)$ ]]; then
        ip="${BASH_REMATCH[1]}"
        # Validation minimale : IPv4 pointée ou IPv6 (contient ':'). Une
        # valeur parasite ne doit jamais finir dans un server= de dnsmasq.
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$ip" == *:* ]]; then
            # Dédoublonnage + plafond : un push anormalement long ne doit
            # pas inonder le fichier.
            if ! grep -qx -- "$ip" <<< "$servers"; then
                if [ -n "$servers" ]; then
                    servers+=$'\n'
                fi
                servers+="$ip"
                count=$((count + 1))
                [ "$count" -ge 8 ] && break
            fi
        fi
    fi

    idx=$((idx + 1))
done

# Écriture : atomicité via tmp+mv si le répertoire est inscriptible (hook
# --up en root) ; écriture directe sinon (hook --route-up en utilisateur
# vpn : le fichier pré-créé vpn:vpn reste inscriptible, pas le répertoire
# /run). Le lecteur (superviseur) tolère une lecture partielle transitoire.
if [ -n "$servers" ]; then
    if touch "${file}.tmp.$$" 2>/dev/null; then
        printf '%s\n' "$servers" > "${file}.tmp.$$"
        mv -f "${file}.tmp.$$" "$file"
    else
        printf '%s\n' "$servers" > "$file"
    fi
fi

exit 0
