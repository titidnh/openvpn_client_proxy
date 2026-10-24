# Revue de sécurité — openvpn_client_proxy

- **Date :** 18 octobre 2026
- **Réviseur :** Vibe (revue indépendante, dépôt complet)
- **Commit audité :** 873800f
- **PR de durcissement :** security/hardening-2026-10

## 1. Périmètre

Revue complète du dépôt : scripts Bash (start.sh, openvpn.sh, vpn-selector.sh,
healthcheck.sh, lib/*.sh), Dockerfile, docker-compose.yml, CI
(.github/workflows/docker-publish.yml), configurations Privoxy (privoxy.config,
default/user action/filter), Makefile, scripts/pre-commit.sh.

## 2. Synthèse

Le code est déjà largement durci : kill switch fail-closed (aucun service ne
démarre si les règles iptables ne se posent pas), early lockdown dès la
première seconde, garde-fous S2 (refus de proxy ouvert non authentifié),
S10 (validation des entiers avant toute évaluation arithmétique), M6 (authkey
Tailscale via fichier 0600, jamais sur la ligne de commande), binaires
Tailscale épinglés par SHA256, CI à permissions minimales avec
"needs: checks". Aucune vulnérabilité critique identifiée : pas d'eval, pas
d'injection shell détectée, secrets absents des arguments de processus.

Les constats ci-dessous ont été corrigés dans la PR security/hardening-2026-10.

## 3. Constats corrigés (PR security/hardening-2026-10)

| # | Constat | Gravité | Correctif |
|---|---------|---------|-----------|
| H1 | .env versionné dans Git — risque qu'un TAILSCALE_AUTHKEY ou PROXY_PASS y soit un jour committé ; aucun .gitignore | Moyenne | .env supprimé du dépôt, remplacé par .env.example, .gitignore ajouté (vpn/, clés, .env) |
| H2 | Conteneur lancé avec les capabilities Linux par défaut et sans no-new-privileges | Moyenne | cap_drop ALL + allow-list minimale (NET_ADMIN, NET_RAW, NET_BIND_SERVICE, SETUID, SETGID, CHOWN, DAC_OVERRIDE, FOWNER, KILL), security_opt no-new-privileges:true, limite pids 256 (deploy.resources.limits.pids) |
| H3 | openvpn tourne en root pendant toute sa vie alors qu il traite des options poussées par le serveur VPN | Moyenne | --user vpn --group vpn --persist-tun --persist-key (OPENVPN_DROP_PRIVILEGES=true par défaut) |
| H4 | Code mort : vpn-startup.sh (legacy, parsing WireGuard faible, openvpn en daemon), lib/proxy.sh et lib/vpn.sh (skeletons TODO jamais sourcés) | Faible | Supprimés du dépôt et de l'image (Dockerfile) |
| H5 | La CI référence SECURITY_REVIEW.md qui n existait pas dans le dépôt | Faible | Ce document |

## 4. Recommandations restantes (backlog)

1. **Bats legacy (Q1)** : la suite legacy (tests/common.bats, dns_blocklist,
   dns_runtime, dot, firewall) est en continue-on-error car des tests sont
   cassés. La réparer et la rendre bloquante.
2. **wg0.conf** : le montage /vpn est en lecture seule, mais ses permissions
   dépendent de l hôte. Documenter "chmod 600 ./vpn/wg0.conf" — la clé privée
   y figure en clair.
3. **Trivy** : le scan ajouté à la CI est informationnel (exit-code 0) ;
   le passer en bloquant (exit-code 1, seuil HIGH/CRITICAL) une fois la
   baseline établie.
4. **read_only: true** : non applicable aujourd hui (sed -i sur /etc, écriture
   dans /tmp, /run, /var/tmp). Envisager un partitionnement volumes + tmpfs
   pour un futur read_only.
5. **Smoke-test avant merge** : le durcissement compose (H2) doit être testé
   sur un déploiement réel (make up + healthcheck) avant merge — certaines
   combinaisons runtime/réseau peuvent réagir aux capabilities retirées.

## 5. Points positifs notables (à préserver)

- Kill switch fail-closed : refus de démarrer les services si setup_iptables
  ou setup_ip6tables échoue ; early lockdown dès le boot.
- S2 : ALLOW_EXTERNAL_PROXY_ACCESS=true exige une authentification, dérogation
  explicite requise pour un proxy ouvert.
- S10 : validation stricte des entiers avant évaluation arithmétique et
  règles iptables (anti-injection).
- M6/M8 : authkey Tailscale lue depuis un fichier 0600 et --socket explicite.
- Ancre DNSSEC 38696 (KSK-2024) + état RFC 5011 persistant via volume.
- Binaires Tailscale téléchargés avec vérification SHA256 (anti supply-chain).
- CI : GITHUB_TOKEN en lecture seule, publication dépendante des checks,
  ShellCheck + tests de régression sécurité bloquants.
- Privoxy et le frontal d'authentification (tinyproxy) tournent en utilisateur
  non privilégié ; authkey et mots de passe jamais exposés en arguments.
