# Journal des corrections — Semaines 1 à 3

> **Périmètre** : corrections issues de l'analyse de sécurité du dépôt
> (`openvpn_client_proxy`), limitées aux semaines 1–3 de la feuille de route.
> Chaque correction est notée **[VALIDÉE]** (test exécuté) ou **[VÉRIFIÉE]**
> (lecture de code + syntaxe + shellcheck), avec la méthode de validation.

---

## Semaine 1 — Étanchéité et arrêt des pannes silencieuses

### 1. C1 — `kill_if_running 0` tuait tout le groupe de processus **[VALIDÉE]**

- **Fichier** : `lib/common.sh` (`kill_if_running`, `is_process_running`, `wait_for_process`)
- **Problème** : `SERVICE_PIDS[...]` initialisés à `0` → `kill 0` envoyait SIGTERM à **tout le groupe** du superviseur. Une simple défaillance VPN arrêtait le conteneur (exit 0) au lieu de redémarrer le service.
- **Correction** :
  ```bash
  kill_if_running() {
      local pid="${1:-}"
      [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0   # refuse vide, 0, non numérique
      kill "$pid" 2>/dev/null || true
  }
  ```
  Même garde-fou appliqué à `is_process_running` et `wait_for_process`.
- **Validation** : test reproduisant le bloc de redémarrage du superviseur avec
  tous les PID à `0` → **le conteneur survit** (`SURVIVANT: le conteneur n'a pas
  été tué`). Avant correction, le trap TERM se déclenchait (reproduit dans
  l'analyse initiale).

### 2. H4 — `set -euo pipefail` global imposé par une lib sourcée **[VÉRIFIÉE]**

- **Fichier** : `lib/common.sh` (ligne `set -euo pipefail` retirée)
- **Problème** : le superviseur long-vivant mourait sur n'importe quel échec de
  commande (`validate_environment` → arrêt silencieux ; `ipt6` en erreur →
  crash en boucle sur noyau sans `ip6_tables`).
- **Correction** : `set -e` retiré de `common.sh` (les scripts one-shot comme
  `healthcheck.sh` gardent leur propre `set -euo pipefail`). `validate_environment`
  est maintenant appelé avec `|| true` dans le superviseur.
- **Validation** : `bash -n` + shellcheck 0 erreurs ; superviseur mocké tourne
  sans crash malgré des échecs simulés (test C7 ci-dessous).

### 3. M7/H4 — `log_json` polluait stdout + JSON invalide **[VALIDÉE]**

- **Fichier** : `lib/common.sh` (`log_json`)
- **Problème** : (a) `log_json` écrivait sur **stdout** → capturé par
  `up_flags=$(build_tailscale_up_flags)` et injecté dans la ligne de commande
  `tailscale up` ; (b) `$message` n'était pas échappé → JSON invalide avec `"`/`\`.
- **Correction** : sortie sur **stderr** + échappement du message.
- **Validation** : `log_json` avec `msg with "quotes" and \ backslash` →
  `python3 json.loads` **OK** ; stdout vide lors de la capture `$(...)`.

### 4. C3 — `lib/firewall.sh` contenait 3 copies concaténées **[VALIDÉE]**

- **Fichier** : `lib/firewall.sh` (1243 → **663 lignes**)
- **Problème** : 3 copies de chaque fonction ; en Bash la dernière écrase les
  autres silencieusement. La version « active » de `ipt_add_853` n'était pas
  idempotente (le CHANGELOG annonçait le contraire) → règles dupliquées à
  chaque refresh DoT.
- **Correction** : une seule définition par fonction (la plus récente),
  `ipt_add_853` rendu idempotent (`-C` avant `-A`).
- **Validation** :
  `grep -hoE '^[a-z_0-9]+\(\) *\{' lib/*.sh | sort | uniq -d` → **vide** ;
  test mock iptables : 2 appels de `ipt_add_853` avec la même IP → **1 seul
  ajout**.

### 5. C2 — La règle du port VPN ouvrait une brèche dans le kill switch **[VALIDÉE]**

- **Fichier** : `lib/firewall.sh` (`setup_iptables`, `setup_ip6tables`)
- **Problème** : `iptables -A OUTPUT -p $VPN_PROTO --dport $VPN_PORT -j ACCEPT`
  sans limite de destination/interface. VPN sur `tcp/443` → **tout le HTTPS**
  pouvait sortir hors tunnel dès que la route basculait sur `eth0`.
- **Correction** : une règle **par remote** extraite de la conf OpenVPN
  (`parse_vpn_remotes`), limitée à `-o $phys_iface -d $ip`. Idem pour
  l'endpoint WireGuard (port de l'`Endpoint`, pas 51820 en dur). Règles
  IPv6 ciblées également. Fallback par port sur l'interface physique (WARN)
  uniquement si aucun remote n'est résolu.
- **Validation** : mock iptables avec conf multi-remotes →
  `-A OUTPUT -o eth0 -d 203.0.113.7 -p udp --dport 1194 -j ACCEPT` présent,
  **aucune** règle `--dport 443` large.

### 6. M2 — Parsing OpenVPN fragile (mono-remote, proto cassé) **[VALIDÉE]**

- **Fichier** : `lib/common.sh` (nouvelles fonctions `parse_vpn_remotes`,
  `get_wireguard_endpoint` ; `get_vpn_port_proto` corrigé)
- **Problème** : un seul `remote` géré, indentation ignorée, `proto tcp4` passé
  tel quel à `iptables -p` (erreur), proto porté par `remote` ignoré.
- **Correction** : `parse_vpn_remotes` émet `ip port proto` par remote,
  normalise `udp4/tcp4/tcp-client/...` → `udp/tcp` ; `get_vpn_port_proto`
  normalise aussi le proto extrait.
- **Validation** : conf de test avec `proto tcp4`, 3 remotes (dont un avec proto
  explicite) → `vpn1.example.com 443 tcp`, `vpn2.example.com 443 tcp`,
  `203.0.113.7 1194 udp` ; `VPN_PROTO=tcp` normalisé.

### 7. H5 — Fenêtre de fuite au démarrage + DoT non strict + gid-owner vpn **[VALIDÉE]**

- **Fichiers** : `lib/firewall.sh` (nouvelle `firewall_early_lockdown`),
  `lib/supervisor.sh`
- **Problème** : (a) politiques par défaut `ACCEPT` pendant les phases 0–2
  (blocklist, dnsmasq, unbound jusqu'à 180 s) → les téléchargements sortaient
  avec l'IP réelle ; (b) en mode DoT les `ACCEPT` vers `DNS_SERVER_1/2:53`
  précédaient le `DROP` du 53 externe → DNS en clair possible hors tunnel ;
  (c) `OUTPUT --gid-owner vpn -j ACCEPT` (tcp+udp) : brèche latente pour tout
  processus du groupe.
- **Correction** :
  - `firewall_early_lockdown()` appelé en **premier** dans `supervise_all` :
    `DROP` partout, puis seulement lo + conntrack + DNS bootstrap + tcp/443
    (blocklists) ;
  - `setup_iptables` retire la règle bootstrap 443 dès que le kill switch
    complet est posé ;
  - les `ACCEPT` port 53 vers `DNS_SERVER_1/2` et `HEALTHCHECK_IP` ne sont
    plus posés en mode DoT (le DROP 53 externe s'applique donc réellement) ;
  - règles `gid-owner vpn` supprimées (v4 et v6).
- **Validation** : mock iptables → `-D OUTPUT -p tcp --dport 443` présent
  après `setup_iptables` ; 0 règle `gid-owner` ; en mode DoT : 0 `ACCEPT`
  vers DNS_SERVER:53 ; les 2 `DROP ! -d 127.0.0.0/8 --dport 53` présents.
  `ipt6` avale maintenant les erreurs avec un WARN unique (H4).

### 8. C6 — `check_vpn_ip` ne pouvait jamais échouer **[VALIDÉE]**

- **Fichier** : `start.sh` (`check_vpn_ip`, nouvelle `capture_real_ip`)
- **Problème** : toutes les branches retournaient 0 → « tunnel opérationnel »
  toujours vrai ; aucune comparaison anti-fuite. En prime,
  `PROXY_USER:PROXY_PASS` était incrusté dans l'URL du proxy interne sans
  auth (divulgation inutile, M6).
- **Correction** :
  - `return 1` si curl indisponible, proxy muet, ou aucune IP publique ;
  - `capture_real_ip()` mémorise l'IP publique réelle **avant** le tunnel
    (phase 0, appelé dans `supervise_all`) ;
  - `check_vpn_ip` échoue si IP via tunnel == IP réelle (**LEAK DETECTED**) ;
  - identifiants retirés de l'URL du proxy interne.
- **Validation** : 4 cas mockés → **PASS** : capture REAL_IP ; passe si IP
  différente ; **échoue sur fuite** ; échoue sans IP.

### 9. H3 — `dig` absent : la validation DoT testait le mauvais résolveur **[VÉRIFIÉE]**

- **Fichier** : `Dockerfile` (`bind-tools` ajouté)
- **Problème** : `test_unbound_dns_robust` retombait sur `nslookup 127.0.0.1`
  (dnsmasq :53, pas unbound :5053) → DoT « validé » même cassé.
- **Correction** : `apk add bind-tools` → `dig @127.0.0.1 -p 5053` maintenant
  disponible dans l'image ; le code de `dot.sh` privilégie déjà `dig` sur le
  **port 5053**.
- **Validation** : lecture de code (`lib/dot.sh:475` utilise `-p 5053` quand
  `dig` existe) + Dockerfile modifié.

---

## Semaine 2 — Fiabilité du superviseur

### 10. C7 — Un échec DNS à l'itération 1 désactivait metrics/refresh à vie **[VALIDÉE]**

- **Fichier** : `lib/supervisor.sh`
- **Problème** : `if [ "$attempt" -eq 1 ]; then start_metrics; start_dot_ip_refresh;
  start_blocklist_refresh; fi` — les `continue` des échecs DNS incrémentaient
  `attempt` avant ce bloc → jamais exécutés.
- **Correction** : drapeaux d'état `_BG_METRICS_STARTED`,
  `_BG_DOT_REFRESH_STARTED`, `_BG_BLOCKLIST_REFRESH_STARTED` armés une seule
  fois, indépendamment du compteur de tentatives.
- **Validation** : test mocké « DNS échoue à l'itération 1, réussit à la 2 » →
  `metrics`, `dot_refresh`, `blocklist_refresh` démarrent bien à l'itération 2
  (l'ancien code ne les lançait jamais), et ne redémarrent pas ensuite.

### 11. C8 — Le refresh blocklist (dnsmasq) redémarrait toute la pile chaque jour **[VÉRIFIÉE]**

- **Fichier** : `lib/dns_blocklist.sh` (`_blocklist_refresh_loop`)
- **Problème** : la boucle tourne dans un sous-shell ; `start_dnsmasq` y met à
  jour `SERVICE_PIDS[dnsmasq]` **dans la copie du sous-shell** → le superviseur
  garde un PID périmé, croit que dnsmasq est mort et redémarre tout (avec C1
  en prime : kill 0).
- **Correction** : le sous-shell ne touche plus à `SERVICE_PIDS` : il relance
  dnsmasq via `pidof` (kill de l'ancien + relance en arrière-plan). Combiné au
  garde-fou C1, un PID périmé côté superviseur est un no-op sûr. Le mode DoT
  garde son `kill -HUP` unbound (déjà correct).
- **Validation** : `bash -n` + shellcheck ; plus aucune écriture
  `SERVICE_PIDS[dnsmasq]` dans la boucle (grep).

### 12. H1 — Healthcheck faux-positif (page d'erreur Privoxy = « healthy ») **[VALIDÉE]**

- **Fichier** : `healthcheck.sh` (`check_http_proxy`)
- **Problème** : les fallbacks 4 (`grep -q "HTTP"` — vrai même sur la page
  503/502 de Privoxy) et 5 (« port ouvert = OK ») validaient le healthcheck
  tunnel mort ; `PROXY_TEST_URL` documenté mais jamais utilisé.
- **Correction** : fallbacks supprimés ; un seul sonde `curl -f` sur
  `$PROXY_TEST_URL` (204 attendu) ; plus de `rm -f /tmp/vpn_healthy` (effet
  de bord) ; support WireGuard (wg0 au lieu de `pidof openvpn`).
- **Validation** : 2 cas mockés → **PASS** : healthcheck **échoue** quand le
  proxy renvoie 503 ; **passe** avec 204.

### 13. H2 — `HEALTHCHECK --timeout=5s` plus court que le script **[VÉRIFIÉE]**

- **Fichier** : `Dockerfile` (`--timeout=20s`)
- **Problème** : pire cas 3 curl × 5 s + DNS > 15 s ; Docker coupait à 5 s.
- **Correction** : `--timeout=20s`, une seule sonde `--max-time 6`.
- **Validation** : lecture Dockerfile.

### 14. H9 — Signal d'arrêt retardé jusqu'à 40 s (SIGKILL par Docker) **[VALIDÉE]**

- **Fichier** : `lib/supervisor.sh` (nouvelle `sleep_wait`, tous les `sleep`
  bloquants remplacés)
- **Problème** : `sleep 40` en avant-plan → le trap TERM ne s'exécutait qu'à la
  fin ; `docker stop` SIGKILL après 10 s sans cleanup.
- **Correction** : `sleep_wait() { sleep "$1" & wait $!; }` partout (40 s,
  10 s, backoff, retries).
- **Validation** : `kill -TERM` envoyé pendant `sleep_wait 30` → **le trap
  s'exécute immédiatement** (`TRAP_EXECUTE`, rc=0).

### 15. M1 — Métriques inexploitables **[VÉRIFIÉE]**

- **Fichiers** : `start.sh` (handler metrics), `lib/supervisor.sh`
- **Problème** : (a) le handler lisait `/tmp/metrics/*` en dur alors que
  `METRICS_DIR=/var/tmp/metrics` → tout à 0 et uptime ≈ 1,7 Md s ; (b)
  `METRIC_RESTART_COUNT = attempt - 1` remis à zéro après stabilisation →
  counter Prometheus décroissant.
- **Correction** : handler paramétré par `METRICS_DIR` (heredoc non coté) ;
  le counter est incrémenté et ne redescend jamais.
- **Validation** : `bash -n` + lecture ; le handler interpole `${METRICS_DIR}`
  à la génération.

### 16. M12 — Backoff et délai de grace non plafonnés **[VÉRIFIÉE]**

- **Fichier** : `lib/supervisor.sh`
- **Problème** : `SKIP_HEALTHCHECK_FIRST_MINUTES` +5 par échec sans limite ;
  backoff jusqu'à 120 s (README : 5→60 s).
- **Correction** : grâce plafonnée à 15 min ; backoff plafonné à 60 s.
- **Validation** : lecture du code modifié.

### 17. M3 — Blocklist « liste brute » : domaines concaténés sur une ligne **[VALIDÉE]**

- **Fichier** : `lib/dns_blocklist.sh`
- **Problème** : `tr -d '[:space:]'` supprimait aussi les fins de ligne →
  `ads.example.comtracker.example.org` (un seul domaine fusionné).
- **Correction** : `awk '{print $1}'` à la place.
- **Validation** : liste brute 2 domaines → **2 lignes** dans le fichier compilé.

---

## Semaine 3 — Fonctionnalités annoncées

### 18. C4 — `VPN_TYPE=wireguard` ne pouvait pas fonctionner (5 causes) **[VALIDÉE en partie]**

- **Fichiers** : **nouveau `lib/wireguard.sh`**, `start.sh`, `lib/supervisor.sh`,
  `healthcheck.sh`, `Dockerfile`
- **Problème** :
  1. `start_wireguard` défini uniquement dans `vpn-startup.sh` (jamais sourcé)
     → `command not found` ;
  2. supervision d'un `sleep infinity` sans sonde réelle ;
  3. healthcheck exigeait `pidof openvpn` → unhealthy permanent en WireGuard ;
  4. firewall : `51820/udp` en dur sans destination ;
  5. parsing `awk '{print $3}'` cassé sur `AllowedIPs = 0.0.0.0/0, ::/0`
     (virgule) et `PrivateKey=xxx` (sans espaces).
- **Correction** :
  - `lib/wireguard.sh` sourcé par `start.sh` et copié dans l'image :
    `wg_get_value` (parsing robuste `Clé = valeur` et `Clé=valeur`),
    `start_wireguard` (création interface, clé privée via stdin sans fuite
    dans ps, peer + endpoint réels, routes 0.0.0.0/1+128.0.0.0/1),
    `wireguard_handshake_ok` (sonde handshake < 180 s) ;
  - `check_vpn_routing` échoue si pas de handshake récent en mode WireGuard ;
  - firewall : règle ciblée sur l'IP/port réels de l'`Endpoint` (C2) ;
  - healthcheck : `wg0` présent au lieu de `pidof openvpn` ;
  - Dockerfile : `lib/wireguard.sh` copié.
- **Validation** : parsing testé → **PASS 6/6** (PrivateKey sans espaces,
  Address multi, AllowedIPs avec virgules, Endpoint, détection de la route par
  défaut `0.0.0.0/0` malgré la virgule, split host:port). Le montage de
  l'interface requiert CAP_NET_ADMIN dans un vrai conteneur (non exécutable
  dans cette sandbox).

### 19. C5 — L'auth proxy (nginx reverse) était inutilisable (CONNECT/407) **[VÉRIFIÉE]**

- **Fichiers** : `start.sh` (`start_nginx_auth` réécrite sur tinyproxy),
  `Dockerfile` (`nginx`+`apache2-utils` remplacés par `tinyproxy`)
- **Problème** : nginx est un reverse proxy : pas de `CONNECT` (HTTPS impossible
  à travers le proxy), `auth_basic` attend `Authorization`+401 alors que les
  clients proxy envoient `Proxy-Authorization` et attendent 407 ;
  `proxy_set_header Authorization ""` supprimait le seul header validable.
- **Correction** : **tinyproxy** en frontal sur `$PROXY_PORT` avec `BasicAuth`
  (407 natif, CONNECT natif), `Upstream http 127.0.0.1:$PROXY_PORT+1` vers
  Privoxy (backend interne inchangé). Refus de démarrer sans auth si tinyproxy
  est absent (plutôt qu'exposer sans protection). Le nom de fonction
  `start_nginx_auth` et la clé `SERVICE_PIDS[nginx]` sont conservés pour
  compatibilité superviseur.
- **Validation** : `bash -n` + shellcheck ; la config tinyproxy générée est
  standard (Port/Listen/BasicAuth/Upstream). Test réseau réel impossible dans
  la sandbox (à confirmer au premier `docker compose up` avec
  `curl -x http://user:pass@host:3128 https://example.com` — attendu : 200).

### 20. M6 (partiel) — Secrets sur la ligne de commande **[VÉRIFIÉE]**

- **Fichier** : `start.sh` (Tailscale)
- **Problème** : `TAILSCALE_AUTHKEY` passé en `--authkey=` sur la ligne de
  commande (visible dans `ps`).
- **Correction** : export via `TS_AUTHKEY` (variable d'environnement lue
  nativement par le CLI tailscale), jamais en argument.
- **Validation** : lecture du code. Les identifiants proxy ne passent plus par
  l'URL du proxy interne (voir C6).

---

## Récapitulatif des fichiers modifiés

| Fichier | Changements |
|---|---|
| `lib/common.sh` | C1 (garde-fou PID), H4 (retrait `set -e`), M7 (log_json stderr + échappement), M2 (`parse_vpn_remotes`, `get_wireguard_endpoint`, normalisation proto) |
| `lib/firewall.sh` | C3 (déduplication 1243→663 lignes), C2 (règles VPN ciblées par remote v4+v6), H5 (`firewall_early_lockdown`, retrait bootstrap 443, DoT strict, retrait `gid-owner vpn`), idempotence `ipt_add_853` |
| `lib/supervisor.sh` | H5 (early lockdown + `capture_real_ip` en tête), C7 (drapeaux `_BG_*`), H9 (`sleep_wait`), M1 (counter monotone), M12 (plafonds), `validate_environment \|\| true` |
| `lib/dns_blocklist.sh` | C8 (refresh sans toucher `SERVICE_PIDS`), M3 (`awk` au lieu de `tr -d`) |
| `lib/wireguard.sh` | **nouveau** — C4 (start_wireguard réel, parsing robuste, sonde handshake) |
| `start.sh` | C6 (`check_vpn_ip` strict + `capture_real_ip` + anti-fuite), C5 (tinyproxy), C4 (source wireguard.sh, sentinel + sonde), M1 (handler metrics paramétré), M6 (TS_AUTHKEY) |
| `healthcheck.sh` | H1 (sonde honnête, PROXY_TEST_URL, plus de fallbacks), C4 (support wg0), retrait des `rm -f` |
| `Dockerfile` | H3 (`bind-tools`), H2 (`--timeout=20s`), C5 (tinyproxy), C4 (copie wireguard.sh + dns_runtime.sh) |

## Vérifications globales

- `bash -n` : OK sur tous les scripts modifiés.
- `shellcheck 0.11.0` (config projet) : **0 erreur**, y compris en
  `--severity=style` filtrée.
- Doublons de fonctions dans `lib/*.sh` : **aucun**
  (`grep -hoE '^[a-z_0-9]+\(\) *\{' lib/*.sh | sort | uniq -d` → vide).
- `bats` (100 tests du dépôt) : **61 passent, 39 échouent — identique à la
  baseline avant modifications** (zéro régression ; les 39 échecs pré-existants
  viennent de mocks `export -f` inopérants et de fonctions inexistantes comme
  `log_info`).
- Tests unitaires dédiés (mocks shell) : C1, C6 (4/4), C7, H1 (2/2), H9, M2,
  M3, C4-parsing (6/6), C2/C3/H5 (mock iptables) — **tous PASS**.
- Flux complet `supervise_all` mocké : early lockdown → capture_real_ip →
  dnsmasq → firewall → privoxy → auth → VPN → check IP ×2 → tailscale →
  drop_caps → attente stabilité — ** conforme**, sortie propre à l'attente 40 s.

## Non couvert (hors périmètre semaines 1–3, confirmé)

- H6/H7/H8 (dnsmasq root, DROP_CAPS, users non-root), M4/M5/M8/M9/M10/M11,
  CI/CD, pinning image, Trivy, nettoyage du code mort (`vpn.sh`, `proxy.sh`,
  `vpn-startup.sh`), encodage mojibake de `common.sh`, versions hétérogènes :
  à traiter en semaine 4.

---

# Round 2 — Corrections issues de la revue indépendante (R1–R6)

> Chaque correctif de la revue a été appliqué puis re-vérifié (bash -n +
> shellcheck --severity=error + tests unitaires ciblés quand le réseau
> sandbox le permettait ; la résolution DNS externe est bloquée dans la
> sandbox, les chemins de résolution sont validés par lecture croisée
> avec resolve_hostname_all, testé en round 1).

## R2b — Fallback par port rouvrait la brèche tcp/443 en mode DoT
- **Fichiers** : `lib/firewall.sh` (`firewall_early_lockdown`, `setup_iptables`), `lib/common.sh` (`resolve_vpn_ips`)
- **Problème** : les `remote` étaient résolus APRÈS le verrouillage DROP ; en mode DoT le port 53 externe est bloqué → résolution impossible → fallback « port-based » large (brèche kill switch).
- **Correction** :
  - Les IPs de TOUS les remotes (OpenVPN et WireGuard, v4 ET v6) sont résolues pendant le bootstrap (`firewall_early_lockdown`), quand le DNS 53 vers DNS_SERVER_* est encore autorisé, et stockées dans `VPN_REMOTE_IPS` (format `ip|port|proto`, le `:` étant ambigu avec IPv6).
  - `setup_iptables` ne résout plus rien : il consomme `VPN_REMOTE_IPS`, pose une règle ciblée `-o <phys> -d <ip>` par endpoint, **compte uniquement les règles réellement posées** (rc iptables vérifié) et **échoue fermé** (`FW_FAILED=1; return 1`) si aucune règle n'a pu être posée. Le fallback par port est **supprimé**.
  - Nouvelle fonction `resolve_vpn_ips` (A + AAAA) ; `get_wireguard_endpoint` retourne un host v6 entre crochets géré (crochets retirés, port par défaut 51820).
  - La section IPv6 de `setup_ip6tables` ne re-résout plus : les endpoints v6 sont déjà couverts par la boucle `VPN_REMOTE_IPS` de `setup_iptables` via `ipt6`.

## R3 — `remote` sans port / CRLF bloquaient le serveur VPN lui-même
- **Fichier** : `lib/common.sh` (`parse_vpn_remotes`)
- **Problème** : port vide → décalage des champs `read -r` → règle iptables invalide, kill switch bloquant le serveur VPN ; CRLF non nettoyé.
- **Correction** (déjà en place, re-testée ici) : `sub(/\r$/,"")`, directive `port` par défaut, ordre `host port proto` sans champ vide, normalisation udp4/tcp-client → udp/tcp.
- **Validation** : test avec `proto tcp`/`port 1195`/`remote` sans port → `vpn.example.com 1195 udp` ; fichier CRLF Windows → host propre, aucun `\r` (vérifié par `od -c`).

## R4 — Handler metrics généré vide (heredoc non cité)
- **Fichier** : `start.sh` (`start_metrics`)
- **Problème** : `<<HANDLER` interpolait tout le contenu à la génération → corps HTTP vide, valeurs figées.
- **Correction** : heredoc **cité** `<<'HANDLER'` ; `METRICS_DIR` injecté séparément via `printf '%q'`. `[VÉRIFIÉE bash -n + lecture]` — la génération est désormais statique.
- **Complément M1** : `METRIC_RESTART_COUNT` n'incrémente qu'à partir d'`attempt=2` (l'itération initiale n'est plus comptée comme restart).

## C8 — Faux « dnsmasq process died » après refresh blocklist
- **Fichier** : `lib/supervisor.sh`
- **Problème** : le sous-shell de refresh relançait dnsmasq sans mettre à jour `SERVICE_PIDS` → le superviseur voyait un PID mort → redémarrage complet quotidien.
- **Correction** : le superviseur relit le PID réel (`pidof dnsmasq | awk '{print $1}'`) avant chaque test de vie.

## H4 — Vérifications explicites après retrait de set -e
- **Fichier** : `lib/supervisor.sh` (+ `start.sh`)
- **Problème** : plus rien ne détectait l'échec des commandes critiques.
- **Correction** : `setup_iptables` en échec → **les services ne démarrent pas** (fail-closed, `continue` + backoff). `start_privoxy` vérifie que le processus survit 1 s (config invalide détectée). `start_nginx_auth` et `start_vpn_service` déjà fail-closed ; le superviseur vérifie leurs retours et ne démarre pas la suite en cas d'échec.

## R5 — `ipt6` avalait les codes retour (déjà corrigé, re-vérifié)
- **Fichier** : `lib/firewall.sh` — wrapper fidèle, alerte unique si ip6tables inutilisable.

## Constats annexes de la revue traités
- **`setup_return_routes`** : les règles `INPUT -d <ip conteneur> -j ACCEPT` (v4 et v6), qui acceptaient TOUT paquet adressé au conteneur depuis n'importe quelle source, sont **supprimées** (les retours conntrack suffisent).
- **`HEALTHCHECK_IP`** : règles 80/443 limitées à l'interface physique (`-o $iface`).
- **En-tête dupliqué** de `lib/firewall.sh` (2 blocs après déduplication C3) : second bloc supprimé.
- **WireGuard (R7/C4 round 2)** :
  - backslashes fantômes en fin de `log_json` (3 commandes « not found ») supprimés ;
  - endpoint résolu **une seule fois** ; `wg set` et la route hôte utilisent la **même IP** ; hostname non résolu → **échec explicite** ; route hote en échec → **échec explicite** (plus de boucle wg0) ;
  - `PresharedKey` et `PersistentKeepalive` pris en charge (keepalive 25 s par défaut derrière NAT, sinon la sonde handshake échoue systématiquement) ;
  - Endpoint IPv6 `[...]:port` géré ;
  - repli **wireguard-go** si le module noyau wireguard est absent.
- **Tailscale M8** : le CLI ne lit pas `TAILSCALE_SOCKET` ; un wrapper `ts_cli` passe `--socket=...` à chaque invocation (`status`, `up`).
- **`capture_real_ip`** : endpoint sans DNS (`https://1.1.1.1/cdn-cgi/trace`, le lockdown ayant vidé le NAT Docker 127.0.0.11), `WARN` explicite si l'IP réelle ne peut être mémorisée (sinon l'anti-fuite est désactivé en silence), option `COLLECT_REAL_IP=false` pour ne pas révéler l'IP réelle à un tiers.
- **`start_privoxy`** : sonde de vie à 1 s → retour 1 si mort immédiate.

## Vérifications round 2
- `bash -n` : OK sur `start.sh`, `lib/common.sh`, `lib/firewall.sh`, `lib/supervisor.sh`, `lib/wireguard.sh`.
- `shellcheck --severity=error` : **0 erreur** sur les 5 fichiers.
- `parse_vpn_remotes` : re-testé (multi-remotes, remote sans port, CRLF, udp4/tcp-client) — conforme.
- Doublons de fonctions : uniquement les stubs gardés par `declare -F` de `lib/vpn.sh`/`lib/proxy.sh` (jamais sourcés) — sans effet à l'exécution.
- Résolution DNS externe : **bloquée dans la sandbox** ; chemins de `resolve_vpn_ips` validés par lecture croisée avec `resolve_hostname_all` (validé round 1) et `bash -n`. À confirmer au premier déploiement réel (T2 de la revue).


---

# Round 3 - Corrections issues de la revue v3 (B1-B5, section 4)

> Chaque correctif a ete applique puis valide par execution quand la sandbox
> le permettait (iptables/ip6tables mockes a codes de retour fideles, tests
> unitaires des parseurs executes). Le resolveur local est bloque dans la
> sandbox : la syntaxe B1 est la version testee par le revieur avec un vrai
> dig 9.18 (4 variantes comparees) ; le repli nslookup a ete teste ici sur
> les deux formats de sortie (busybox et classic).

## B1 - resolve_vpn_ips : la syntaxe combinee ne retournait que l'IPv6
- **Fichier** : `lib/common.sh` (`resolve_vpn_ips`)
- **Probleme** : la requete dig avec deux types sur un seul nom emet
  « Warning, extra type option » et le DERNIER type l'emporte : resultat
  vide ou IPv6 seulement. Tout remote par nom d'hote echouait donc a la
  resolution, et le kill switch (ferme) empechait le conteneur de demarrer.
  Le repli nslookup n'imprimait que les non-IPv4 et laissait passer la
  ligne du serveur.
- **Correction** : requete double explicite (A puis AAAA en une invocation
  multi-query, testee par le revieur), +time=2 +tries=1 (sinon ~20 s par
  serveur muet, plusieurs minutes pour 10 remotes). Repli nslookup reecrit :
  gere les formats busybox (Address 1: ip host) et classic (Addresses: ip, ip),
  ignore le serveur lui-meme.
- **Validation** : repli nslookup teste sur les deux formats (2 IP extraites
  chacune) ; syntaxe conforme a la matrice du revieur (4 variantes).

## B5 - parse_vpn_remotes : proto faux dans 3 cas
- **Fichier** : `lib/common.sh` (`parse_vpn_remotes`)
- **Probleme** : la version une-passe ne connaissait port/proto que s'ils
  etaient AVANT le remote, et ignorait proto quand le port etait absent :
  proto tcp -> regle udp/443 -> VPN bloque par le kill switch.
- **Correction** : deux passes awk (le fichier passe deux fois) - la 1re
  memorise dport/dproto quel que soit l'ordre, la 2e traite les remotes ;
  dproto utilise quand le 3e champ n'est ni un port ni un proto explicite.
- **Validation** : les 3 cas de la revue (D/E/F) + CRLF + multi-remote +
  tcp-client tous conformes (teste).

## B3 - continue sans nettoyage : services orphelins, blocage permanent
- **Fichier** : `lib/supervisor.sh`
- **Probleme** : un echec de start_privoxy / start_nginx_auth /
  start_vpn_service / setup_iptables faisait continue sans arreter les
  services deja lances : privoxy orphelin, bind impossible a l'iteration
  suivante, blocage jusqu'au redemarrage du conteneur.
- **Correction** : stop_stack() (kill des PID enregistres + pkill -x
  privoxy/tinyproxy pour les orphelins, remise a 0 des PID) appele avant
  chaque continue de la section firewall/services.
- **Validation** : test unitaire - 2 processus lances, stop_stack, plus
  aucun vivant.

## B4 - ipt6 : code retour toujours 0 (non corrige en round 2)
- **Fichiers** : `lib/firewall.sh` (ipt6, setup_ip6tables)
- **Probleme** : « if ip6tables ...; then return 0; fi; local rc=$? » -
  or $? apres un if faux vaut 0, donc rc etait TOUJOURS 0 : les tests -C
  donnaient des faux positifs, les regles IPv6 853 n'etaient jamais posees.
  En outre setup_ip6tables (appele apres setup_iptables) commencait par
  ipt6 -F et effacait les regles IPv6 des remotes sans les re-poser.
- **Correction** : ip6tables avec || rc=$? (rc fidele) ; alerte unique si
  ip6tables inutilisable ; les endpoints IPv6 de VPN_REMOTE_IPS sont
  re-poses dans setup_ip6tables apres le flush (interface physique
  determinee une fois).
- **Validation** : avec ip6tables mocke rc-fidele - -C regle absente -> 1,
  commande invalide -> non nul, commande valide -> 0.

## B2 - tinyproxy rejetait presque tous les mots de passe reels
- **Fichier** : `start.sh` (start_nginx_auth)
- **Probleme** : BasicAuth n'accepte quasiment que [A-Za-z0-9._-] (teste
  1.11.1 par le revieur : s3cr3t! p@ss etc -> Syntax error, demon mort) ;
  start_nginx_auth ne detectait pas la mort immediate et renvoyait 0 ->
  boucle de redemarrage.
- **Correction** : validation stricte ^[A-Za-z0-9._-]{1,64}$ (user) et
  {1,128} (pass) avec erreur explicite + hint (Squid/3proxy pour mots de
  passe arbitraires) ; sonde de vie a 1 s (sleep_wait 1 + is_process_running)
  -> return 1.
- **Documentation** : README mis a jour - nginx->tinyproxy partout
  (13 occurrences), limite de jeu de caracteres documentee sur PROXY_PASS,
  COLLECT_REAL_IP documente.
- **Validation** : test du jeu de caracteres (accepte s3cr3t / Passw0rd,
  rejette s3cr3t! / p@ss / espace).

## Section 4 - Points non bloquants traites
- **(1) Tailscale TS_AUTHKEY** : le CLI up ne lit pas cette variable
  (confirme par cmd/tailscale/cli/up.go). La cle est ecrite dans
  /run/tailscale_authkey (0600) et passee via --auth-key=file:/...,
  fichier supprime apres le up.
- **(2) Liste d'IP figee** : non traite ce tour (rafraichissement
  periodique de VPN_REMOTE_IPS) - documente comme dette ; un changement
  d'IP fournisseur necessite un redemarrage.
- **(3) WireGuard + DoT** : start_wireguard reutilise l'IP de
  VPN_REMOTE_IPS (resolue au bootstrap) au lieu de re-resoudre apres DROP -
  valide par test (endpoint = 203.0.113.7, pas de resolution).
- **(4) Endpoint WG IPv6** : get_wireguard_endpoint reecrit -
  [2001:db8::1]:51820 -> 2001:db8::1 51820 (valide), host:port et host
  sans port OK.
- **(5) tcp/443 bootstrap** : COLLECT_REAL_IP defaut false ; n'ouvre que
  vers -d 1.1.1.1 ; le 443 large n'est ouvert que si ENABLE_DNS_BLOCKLIST.
  capture_real_ip aligne (defaut false) et README documente.
- **(6) H4** : firewall_early_lockdown verifie les 3 politiques
  iptables -P ... DROP et echoue explicitement (return 1) ; supervise_all
  s'arrete proprement si le lockdown echoue (pas de kill switch -> pas de
  demarrage).

## Verifications round 3
- bash -n : OK sur tous les scripts ; shellcheck --severity=error : 0 erreur.
- Fail-closed re-teste de bout en bout (mocks iptables) : hostname non
  resoluble -> VPN_REMOTE_IPS vide -> failing closed, setup_iptables rc=1,
  aucun fallback par port.
- Flux nominal re-teste : conf multi-remotes -> 3 regles ciblees
  -o eth0 -d <ip> posees, proto/port corrects.
- ipt6 : codes retour fideles (3 cas).
- parse_vpn_remotes : 7 scenarios conformes.
- Non testable ici : vrai dig (resolveur bloque sandbox), vrai
  tinyproxy/privoxy non installes, pas de namespace reseau root pour le
  banc iptables reel. Ces chemins portent la syntaxe validee par le revieur
  avec les vrais outils.

## Dette restante (a planifier)
- (2) : rafraichissement periodique de VPN_REMOTE_IPS (changement d'IP
  fournisseur).
- compose : disable_ipv6=0 et blocklist-cache:/tmp inchanges (M9/M5,
  semaine 4).
- ipt6_must encore non appelee (les politiques v6 sont gerees via ipt6 +
  alerte) - a brancher si un echec v6 doit etre bloquant.
- CI : integrer le banc netns-tests du revieur (scenarios A-H) comme tests
  de non-regression (necessite root/unshare).

---

## Round 4 — revue v4 (round 3 de verification) : points restants 3.1-3.6

La revue v4 valide B1-B5 sans nouveau defaut bloquant. Corrections des points non bloquants 3.1 a 3.6 :

### 3.3 — Blocs `<connection>` avec port/proto par bloc (parse_vpn_remotes, lib/common.sh)
**PROBLEME** : la 1re passe retenait la DERNIERE valeur globale de port/proto -> le 1er bloc `<connection>` heritait des valeurs du dernier (regle tcp/443 fausse -> remote bloque).
**CORRECTIF** : la 1re passe memorise `bport`/`bproto` PAR BLOC et les remontees des remotes du bloc (`blkstart`) ; les valeurs sont appliquees a la fermeture `</connection>` (ordre remote-avant-port legal OpenVPN gere). La 2e passe restitue par remote de bloc via `blkseen`.
**VALIDATION** : 14/14 cas - blocs `<connection>` (port/proto apres OU avant remote), multi-remote par bloc, remote explicite dans bloc, melange bloc/global, CRLF, multi-remote, tcp-client, bare remote, proto seul.

### 3.1 — Delais de resolution et deduplication (resolve_vpn_ips + firewall_early_lockdown)
**PROBLEME** : repli nslookup sans borne (~6 s/serveur muet) et tente meme si dig a deja echoue ; hostnames partages par plusieurs remote resolus plusieurs fois.
**CORRECTIF** :
- repli nslookup tente UNIQUEMENT si dig est absent (sinon double attente) et borne par `timeout 5` (busybox nslookup n'a pas -timeout=).
- `firewall_early_lockdown` : cache `RESOLVE_CACHE` (declare -A) - chaque hostname resolu UNE fois, tous partages la meme liste d'IP.
**VALIDATION** : mock avec 3 remotes sur 2 hostnames -> 2 appels de resolution seulement ; liste VPN_REMOTE_IPS complete (3 entrees) ; regles -d correctes.

### 3.2 — Reprise apres echec de resolution au boot (lib/supervisor.sh)
**PROBLEME** : VPN_REMOTE_IPS calculee une seule fois ; DNS muet au boot -> setup_iptables echoue a chaque iteration -> boucle infinie (stop_stack + sleep 30).
**CORRECTIF** : compteur `FW_FAIL_COUNT` d'echecs consecutifs ; apres `FW_FAIL_MAX` (5) echecs -> `return 1` de supervise_all : le conteneur sort (code 1) et la politique de redemarrage Docker relance un bootstrap complet (qui re-resoudra les remotes). Compteur remis a 0 sur succes.
**VALIDATION** : harnais mocke - sortie au 5e echec consecutif exactement, compteur reinitialise apres un succes.

### 3.4 — Endpoint WireGuard IPv6 litteral (lib/wireguard.sh)
**PROBLEME** : `wg set` recevait `2001:db8::1:51820` sans crochets (invalide) et `ip route add` utilisait une passerelle IPv4 pour une destination v6.
**CORRECTIF** : `endpoint_addr` reconstruit avec crochets si l'IP contient `:` ; route hote v6 via `ip -6 route` et passerelle v6 (`ip -6 route show`), branche v4 inchangee.
**VALIDATION** : mock wg/ip de bout en bout - `wg set wg0 peer ... endpoint [2001:db8::1]:51820 ...` et `ip -6 route add 2001:db8::1 via 2001:db8::ff dev eth0` ; IPv4 sans crochets toujours OK.

### 3.5 — Documentation residuelle (README.md, docker-compose.yml)
**CORRECTIF** :
- README :814 « hashed with bcrypt via htpasswd » (faux depuis tinyproxy) -> « stored in clear text in a 0600 tinyproxy config file ».
- compose : l'exemple `PROXY_PASS: "s3cr3t!"` (desormais refuse par la validation) -> `"Passw0rd"` avec commentaire sur la limite `[A-Za-z0-9._-]`.

### 3.6 — Details mineurs
- `capture_real_ip` : log INFO unique « leak detection disabled - COLLECT_REAL_IP=false » au lieu d'une sortie muette (start.sh).
- Variable `rest` inutilisee retiree de start_wireguard (SC2034, lib/wireguard.sh).
- `ipt6_must` toujours pas appelee : dette declaree (echec de `ip6tables -P DROP` non bloquant).
- `stop_stack` ne tue pas wireguard-go/tailscaled : accepte (concus pour survivre).

### Verification globale round 4
- `bash -n` OK sur start.sh, healthcheck.sh, lib/*.sh.
- `shellcheck --severity=error` : 0 erreur.
- Doublons de fonctions : uniquement le stub `find_vpn_interface` (lib/vpn.sh non source - connu).
- Tests cibls : parseur 14/14, dedup 2 appels/2 hostnames, compteur FW 5 echecs -> return 1, WG v6 brackets + ip -6 route, flux firewall mocke conforme.

### Dette restante (declaree, hors perimetre semaines 1-3)
- Rafraichissement periodique de VPN_REMOTE_IPS (fournisseur qui change d'IP).
- compose : `disable_ipv6=0`, `blocklist-cache:/tmp` (M5/M9).
- Banc netns-tests en CI (necessite root/unshare).
- `ipt6_must` non branchee.

---

## Round 5 - revue v5 (round 4 de verification) : correctifs des 2 reservations

La revue v5 valide 3.2/3.3/3.4/3.5/3.6 du round 4, sans regression, avec deux reservations :

### v5-3.1 - Cache de resolution inoperant (sous-shell) (lib/firewall.sh)
**PROBLEME** : resolve_cached etait appelee dans une substitution de processus
(`done < <(resolve_cached "$r_host")`) : l'ecriture dans RESOLVE_CACHE se perdait
dans le sous-shell - 3 appels reels pour 3 remotes sur 2 hostnames (attendu 2).
**CORRECTIF** : resolve_cached alimente le cache dans le shell PARENT (plus de
substitution de processus), puis la lecture se fait via `<<< "${RESOLVE_CACHE[$host]}"`.
Applique aux deux branches (openvpn et wireguard).
**VALIDATION** :
- openvpn : 3 remotes / 2 hostnames (dont un hostname a 2 IP) -> 2 appels reels
  seulement, VPN_REMOTE_IPS complete (5 entrees).
- wireguard : endpoint par nom -> 1 seul appel.

### v5-3.2 - Blocs `<connection>` : heritage des options globales (lib/common.sh)
**PROBLEME** : une option non precisee dans un bloc retombait sur udp/1194 au lieu
d'heriter de la valeur globale (norme OpenVPN) - `proto tcp` global + bloc sans
proto donnait une regle udp fausse -> serveur VPN bloque.
**CORRECTIF** : en 2e passe, si `blkport[k]`/`blkproto[k]` est vide, on retombe sur
`dport`/`dproto` (les globales, deja lues en 1re passe quel que soit l'ordre).
**VALIDATION** : 15/15 - les 4 cas du revioir (proto global seul, port+proto globaux,
port redefini dans le bloc, globales APRES les blocs) + les 11 cas de non-regression
du round 4 (blocs avec valeurs propres, ordre remote avant/apres port/proto,
multi-remote par bloc, melange bloc/global, CRLF, tcp-client, bare remote).

### v5-3.3 - Details mineurs (lib/common.sh)
- Indentation du bloc `if command -v dig` dans resolve_vpn_ips.
- Commentaire duree corrigee : ~4 s par serveur muet (mesure revioir), pas ~20 s.

### Verification globale round 5
- bash -n OK ; shellcheck --severity=error : 0 erreur ; aucun doublon de fonction.
- Parseur 15/15 ; cache 2 appels / 5 entrees (openvpn), 1 appel (wireguard) ;
  compteur pare-feu 5 echecs -> return 1 ; WG v6 crochets + ip -6 route inchanges.

---

## Round 6 - revue v6 (round 5 de verification) : rport + BOM UTF-8

La revue v6 valide les deux correctifs du round 5 (cache 2 appels, heritage global 16/16)
sans regression. Restaient deux limites mineures du parseur, corrigees ici :

### v6-3.1 - Directive rport ignoree (parse_vpn_remotes, lib/common.sh)
**PROBLEME** : rport fixe le port DISTANT (directive OpenVPN valide, y compris dans
un bloc <connection>) mais le parseur ne lisait que port -> regle fausse, serveur bloque.
**CORRECTIF** : rport memorise comme port distant (global drport / par bloc brport),
prioritaire sur la directive port ; un port explicite sur la ligne remote reste
au-dessus (norme OpenVPN). Heritage global dans les blocs identique a port/proto.
**VALIDATION** : 5 cas rport - global seul, dans un bloc, rport vs port (rport gagne),
port explicite sur remote (remote gagne), heritage global dans bloc.

### v6-3.2 - BOM UTF-8 en tete de fichier (parse_vpn_remotes, lib/common.sh)
**PROBLEME** : un .ovpn enregistre avec BOM (Notepad Windows) dont la 1re ligne est
proto/remote/port n'etait pas reconnu (directive prefixee par \xEF\xBB\xBF).
**CORRECTIF** : sub(/^\xef\xbb\xbf/, "") en tete de la regle de nettoyage
(avant sub(/\r$/)), inconditonnel - le BOM ne colle quau 1er champ du fichier.
**VALIDATION** : BOM + proto en 1re ligne ; BOM + bloc <connection> en 1re ligne.

### Verification globale round 6
- Parseur : 22/22 (5 rport, 2 BOM, 4 heritage global v5, 11 non-regression round 4).
- bash -n OK ; shellcheck --severity=error : 0 erreur ; doublons : seul le stub
  find_vpn_interface (lib/vpn.sh non source, connu).
- Non-regression du flux : cache openvpn 2 appels / 5 entrees, cache wireguard 1 appel,
  compteur pare-feu 5 echecs -> return 1, WG v6 crochets + ip -6 route.

### Dettes inchangees (declarees)
- VPN_REMOTE_IPS calculee une seule fois au bootstrap ; sortie apres 5 echecs pare-feu.
- ipt6_must non appelee ; stop_stack ne tue pas wireguard-go/tailscaled.
- compose : disable_ipv6=0, volume nomme sur /tmp.
- shellcheck --norc sur lib/*.sh : 12 SC2034 + 5 SC2154 (dns_runtime/dns_blocklist,
  faux positifs sur cles de tableaux associatifs) - a regarder a l occasion.

---

## Round 7 - revue v7 (round 6 de verification) : croisement de portee rport/port

La revue v7 valide rport + BOM sous mawk ET busybox awk (celui de l image Alpine),
sans regression. Un seul point restait :

### v7-3 - rport GLOBAL ecrasait le port PROPRE AU BLOC (parse_vpn_remotes)
**PROBLEME** : v6 appliquait la retombee rport -> port en fin de calcul, sans
distinction de portee : `rport 443` global + bloc avec `port 8443` donnait 443
au lieu de 8443 (l option la plus locale doit lemporter).
**CORRECTIF** : resolution du port PAR PORTEE, du plus local au plus global :
rport du bloc > port du bloc > rport global > port global ; un port explicite sur
la ligne remote reste au-dessus de tout (norme OpenVPN).
**VALIDATION** : banc parse_tests.sh (39 cas, fourni par le revioir, ajoute au depot)
- 39/39 sous mawk. Le revioir a valide le comportement identique sous busybox awk
  (image Alpine) sur les 39 cas ; la sandbox n a pas busybox (pas de root pour
  installer) - la reference reste le banc du revioir.
- Cas corriges : rport global + bloc avec port (8443 gagne), rport de bloc vs
  rport global (bloc gagne), lport ignore, BOM sur ligne de commentaire.

### Tests : parse_tests.sh ajoute a la racine du depot
Banc autonome (ni root ni reseau) : 39 cas couvrant CRLF, BOM, port/rport/proto
globaux et par bloc, heritage, ordre quelconque, IPv6 litteral, udp6/tcp6-client,
multi-remote par bloc, commentaires, remote-random, lport, croisements de portee.
Usage : CODE=. bash parse_tests.sh (option : PATH=shim-busybox pour tester avec
l awk BusyBox de l image).

### Verification globale round 7
- bash -n OK ; shellcheck --severity=error : 0 erreur ; doublons : stub connu.
- Non-regression : cache resolution, compteur pare-feu, WG v6 - inchanges.

---

## Round 8 - bug production : OpenVPN re-resout le hostname et bute sur le kill switch

**SYMPTOME** (conteneur reel) : pare-feu OK (2 remotes resolus au bootstrap,
156.146.62.56 et 89.222.97.196), puis :
`write UDPv4 []: Operation not permitted` vers 89.37.173.19:1194 -
une TROISIEME IP du round-robin DNS que le pare-feu n a jamais autorisee.

**CAUSE RACINE** : le pare-feu autorise les IP resolues au bootstrap
(VPN_REMOTE_IPS), mais OpenVPN demarre avec la config d origine et
re-resout lui-meme le hostname -> peut obtenir une autre IP du
round-robin -> bloquee par le kill switch. C est la dette "VPN_REMOTE_IPS
figee" qui mordait en production (deux VPN : le premier marche par chance
- meme IP tiree ; le second echoue).

**CORRECTIF (approche : epingler OpenVPN sur les memes IP que le pare-feu)** :
1. lib/firewall.sh (firewall_early_lockdown) : export de VPN_REMOTE_MAP,
   carte "host=ip1,ip2 ..." construite depuis RESOLVE_CACHE (deja utilisee
   pour poser les regles).
2. openvpn.sh : si VPN_REMOTE_MAP est present, generation de
   vpn.resolved.conf OU chaque ligne `remote host [port] [proto]` avec un
   hostname mappe est remplacee par une ligne par IP resolue (port/proto
   conserves, autres directives intactes), chmod 600, et OpenVPN demarre
   sur cette config. Plus AUCUNE resolution DNS au demarrage d OpenVPN.

**VALIDATION** (mock complet) :
- firewall_early_lockdown exporte bien
  VPN_REMOTE_MAP="vpn.example.com=156.146.62.56,89.222.97.196"
  et VPN_REMOTE_IPS avec les 4 couples IP|port|proto.
- config resolue : 2 lignes remote hostname -> 4 lignes remote IP
  (2 IP x 2 remotes), directives conservees (client, proto, resolv-retry).
- Si RESOLVE_CACHE est vide (remotes en IP litterales), pas de map, pas de
  rewrite - comportement inchange.

**NOTE** : la re-resolution periodique des IP (fournisseur qui change d IP
pendant la vie du conteneur) reste une dette - ce correctif garantit la
coherence pare-feu/OpenVPN au demarrage, ce qui corrige le cas observe.

---

## Round 9 - retour production : /vpn monte en lecture seule

**SYMPTOME** : `/usr/local/bin/openvpn.sh: line 62: /vpn/vpn.resolved.conf:
Read-only file system` puis plus rien - le conteneur restait bloque
("waiting for VPN tunnel..." sans fin).

**CAUSE** : le volume /vpn est monte en lecture seule (ro) dans docker-compose.
Le round 8 ecrivait la config resolue dans $dir (/vpn). De plus, avec set -e,
l echec du redirect tuait openvpn.sh AVANT le fallback WARN prevu - le
processus VPN mourait silencieusement et le superviseur attendait indefiniment.

**CORRECTIF** (openvpn.sh) :
1. La config resolue est ecrite dans /tmp/vpn.resolved.conf (pas dans /vpn).
   --cd reste sur $dir : les chemins RELATIFS de la config (certificats, cles,
   vpn.auth) continuent d etre resolus dans /vpn.
2. Redirect tolere l echec (|| true + test -s) : si la generation echoue,
   WARN + config d origine - jamais de mort silencieuse.

**VALIDATION** (mock) : generation dans /tmp OK, remotes IP corrects,
directives conservees ; le flux map -> config reste identique par ailleurs.

**NOTE** : les deux IP de ce log (185.183.104.43, 89.37.173.23) correspondent
aux remotes autorises au pare-feu - l epinglage du round 8 fonctionne, seule
l ecriture posait probleme.

---

## Round 10 - revue v8 (rounds 7 a 9) : secrets en volume persistant + BOM

### v10-3.1 - La config resolue (avec secrets inline) etait ecrite dans /tmp, monte sur un volume persistant **[VALIDEE]**

- **Fichier** : `openvpn.sh`
- **Probleme** : docker-compose.yml monte le volume nomme `blocklist-cache`
  sur /tmp (persistant sur l hote, survit a `docker compose down` sans `-v`).
  La config resolue copiait INTEGRALEMENT vpn.conf - donc `<key>`,
  `<auth-user-pass>` et identifiants inline des .ovpn de fournisseurs - dans
  ce volume. De plus le fichier etait cree en 644 (umask par defaut) pendant
  un court instant avant le chmod 600.
- **Correction** :
  1. `umask 077` : le fichier est cree directement en 600, aucune fenetre.
  2. `mktemp /dev/shm/...` (tmpfs memoire, jamais persiste), avec repli
     `/run` puis `/tmp` si le tmpfs est absent.
- **Validation** : bloc mktemp execute sous `set -euo pipefail` ->
  fichier cree en mode 600 dans /dev/shm ; `bash -n` OK.

### v10-3.2 - remote non reecrit en cas de BOM UTF-8 (openvpn.sh, sans avertissement) **[VALIDEE]**

- **Probleme** : l awk de reecriture n avait pas le nettoyage de
  parse_vpn_remotes (BOM, CR). Un `remote host` en 1re ligne precede d un BOM
  n etait pas reecrit -> OpenVPN re-resolvait le hostname -> IP non
  autorisee par le kill switch, sans aucun message.
- **Correction** :
  1. Nettoyage identique au parseur du pare-feu en tete de reggle :
     `sub(/^\xef\xbb\xbf/, ""); sub(/\r$/, "")`.
  2. `END` : WARN sur /dev/stderr si un hostname de la ligne remote n a pas
     ete epingle par VPN_REMOTE_MAP (silence supprime).
- **Validation** (awk reel extrait de openvpn.sh, 5 scenarios) :
  BOM 1re ligne + CRLF -> reecrit ; CRLF sans port -> reecrit ;
  hostname hors carte -> WARN emis ; remote IP -> inchange ;
  2 remotes x 2 IP -> 4 lignes correctes. Le `2>/dev/null` qui masquait le
  WARN a ete retire.

**DETTE** (inchangee) : les IP restent figees au demarrage du conteneur ;
une re-resolution periodique ou un restart Docker reste le correctif de
fond. /tmp en volume nomme reste a restreindre (dette declaree).
