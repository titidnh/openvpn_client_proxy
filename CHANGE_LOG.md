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
