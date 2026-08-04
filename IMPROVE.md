# Plan d'amelioration detaille - Juillet 2026

## 1) Objectif du mois

Augmenter fortement la stabilite de l'image VPN proxy et reduire les incidents de production en traitant prioritairement:
- la resilience reseau (DoT, healthchecks, auto-restart),
- la robustesse du demarrage/supervision,
- la qualite CI/CD (tests, securite, reproductibilite),
- la maitrise de la performance (CPU/RAM et latence DNS/proxy).

Objectif cible fin juillet 2026:
- disponibilite service >= 99.9%,
- MTTR < 5 min,
- redemarrages non planifies < 1/jour,
- echec healthcheck < 0.5% sur 24h,
- latence DNS p95 < 80 ms (cache chaud) et p95 proxy HTTP CONNECT stable.

---

## 2) Constat technique actuel

Le projet est solide en base (kill switch, supervision, DoT optionnel, metriques), mais plusieurs points peuvent provoquer des faux positifs, des degradations progressives ou des pannes silencieuses.

Principaux fichiers concernes:
- start.sh
- healthcheck.sh
- Dockerfile
- docker-compose.yml
- .github/workflows/docker-publish.yml
- privoxy.config
- default.filter
- default.action

---

## 3) Priorites critiques (P0) - a traiter en premier

### P0.1 - Bug de refresh DoT incomplet (risque coupure DNS)

Probleme:
- Le refresh dynamique met a jour les regles iptables (port 853) quand l'IP du resolver DoT change.
- Mais la configuration unbound continue a pointer vers les anciennes IP forward-addr.
- Resultat possible: regles firewall coherentes mais forward DoT casse => resolution DNS KO jusqu'au restart.

Impact:
- perte de resolution DNS,
- faux etat "service up" puis echec trafic,
- instabilite intermittente difficile a diagnostiquer.

Action:
- Lors d'un changement d'IP DoT, regenerer unbound.conf puis recharger unbound (reload gracieux) ou basculer en mode forward-addr hostname natif quand possible.
- Ajouter un test post-refresh: requete DNS via 127.0.0.1:53 + via 127.0.0.1:5053.

Critere d'acceptation:
- changement IP DoT simule sans interruption DNS observable.

### P0.2 - Healthcheck potentiellement trompeur

Problemes:
- En mode OpenVPN TCP, le healthcheck peut sortir en succes apres simple test de port distant, meme si le tunnel n'est pas operationnel.
- Le test HTTP final depend de example.com (dependance externe inutilement fragile).

Impact:
- faux positifs de sante,
- mauvaise orchestration (container considere sain alors que le tunnel est inutilisable).

Action:
- Changer la logique: ne jamais valider seulement sur un port VPN reachable.
- Verifier combinaison minimale:
  1) process OpenVPN vivant,
  2) route effective via tun/tap,
  3) requete HTTP(S) proxy sur endpoint fiable (avec fallback),
  4) eventuellement test DNS local (127.0.0.1).
- Remplacer endpoint unique par une liste de sondes (ex: 204 + IP check fallback).

Critere d'acceptation:
- zero faux positif reproduit sur scenarios tunnel coupe mais serveur VPN joignable.

### P0.3 - Surface de fuite DNS en mode DoT

Probleme:
- Le port 53 vers DNS_SERVER_1/2 reste autorise, y compris quand DoT est actif.
- Cela laisse une voie de contournement potentielle si un process sort explicitement vers ces resolvers.

Impact:
- risque de fuite metadata DNS,
- ecart entre promesse "DoT strict" et comportement effectif.

Action:
- Limiter l'autorisation 53 stricte a la phase bootstrap (resolution initiale), puis la retirer.
- Alternative: autoriser temporairement uniquement un process/UID dedie a la resolution initiale.

Critere d'acceptation:
- en mode DoT, aucune sortie 53 externe apres bootstrap.

---

## 4) Priorites hautes (P1)

### P1.1 - Hardening reel des capabilities

Probleme:
- Le drop actuel agit surtout sur le bounding set, mais ne garantit pas une reduction complete des privileges effectifs/permis deja actifs.

Action:
- Clarifier la menace et appliquer un drop complet (setpriv/capsh/exec strategy) ou separation stricte des processus privilegies/non privilegies.
- Verifier par inspection runtime des capabilities effectives.

### P1.2 - Fiabilite du superviseur

Problemes:
- script monolithique tres long, chemins d'erreur nombreux,
- risque de regressions lors de modifications futures,
- complexite de debug en incident.

Action:
- Refactoriser start.sh en modules/fonctions par domaine (firewall, dns, proxy, vpn, tailscale, metrics).
- Ajouter timeout defensifs partout ou une commande reseau peut bloquer.
- Ajouter journalisation d'etat standardisee pour transitions critiques.

### P1.3 - CI/CD insuffisante pour la stabilite

Problemes:
- Pipeline actuel: build/push principalement,
- absence de gates de qualite avant publication (tests shell, smoke tests runtime, scans).

Action:
- Ajouter workflows PR et pre-push avec:
  - shellcheck + shfmt,
  - tests de demarrage container (vpn off/on, DoT off/on),
  - test healthcheck,
  - scan securite image (ex: Trivy),
  - policy de blocage si echec.

### P1.4 - Reproductibilite des builds

Probleme:
- dependances apk non figees; variabilite forte d'une build a l'autre.

Action:
- Mettre en place strategie de pinning (version image base, lot paquets critiques),
- routine mensuelle de mise a jour controlee,
- changelog securite associe.

---

## 5) Priorites moyennes (P2)

### P2.1 - Performance proxy/filtrage

Probleme:
- Regles Privoxy tres agressives (regex nombreuses) pouvant augmenter CPU/latence et casser certains sites.

Action:
- Mesurer cout CPU et latence par famille de filtres,
- introduire profils: normal / strict,
- activer les filtres les plus couteux uniquement en mode strict.

### P2.2 - Qualite des listes de filtres

Problemes:
- Entrees potentiellement obsoletes/fictives,
- risque de faux positifs ou inefficacite.

Action:
- Curer la liste avec validation periodique,
- separer "core stable" et "experimental",
- ajouter un mecanisme de tests de non-regression web.

### P2.3 - Ressources memoire et modes

Probleme:
- limite 128M potentiellement tendue selon options activees (DoT, auth, tailscale), risque OOM/restarts.

Action:
- definir profils ressources recommandes par mode,
- monitorer RSS et pic memoire,
- ajuster limites compose/documentation selon mesures reelles.

---

## 6) Plan d'execution - Juillet 2026

### Semaine 1 (1-7 juillet) - Stabilite critique

1. Corriger refresh DoT + reload unbound.
2. Refaire healthcheck anti faux positifs.
3. Durcir regles DNS en mode DoT (53 externe post-bootstrap bloque).
4. Ajouter metriques d'erreurs DNS/DoT.

Livrables:
- patchs scripts,
- tests manuels reproductibles,
- note d'impact.

### Semaine 2 (8-14 juillet) - Qualite operationnelle

1. Refactor partiel start.sh (extraction modules critiques).
2. Ajout timeouts/retries uniformes.
3. Logs de transitions et causes de restart normalises.

Livrables:
- structure scripts simplifiee,
- runbook incident mis a jour.

### Semaine 3 (15-21 juillet) - CI/CD et securite

1. Ajouter pipeline PR quality gate.
2. Ajouter shellcheck + shfmt + smoke tests container.
3. Ajouter scan image et rapport vulnerabilites.
4. Definir regle: pas de publish si gate rouge.

Livrables:
- workflows GH Actions complets,
- badges et docs de verification.

### Semaine 4 (22-31 juillet) - Performance et fiabilisation finale

1. Benchmark perf proxy/DNS (normal vs strict).
2. Profilage memoire selon modes.
3. Nettoyage filtres et reduction faux positifs.
4. Validation soak test 24-72h (restart, DNS, tunnel, auth).

Livrables:
- rapport benchmark,
- profils recommandes,
- release candidate stable fin juillet.

---

## 7) KPIs de suivi (a instrumenter des la S1)

- Stability
  - uptime % sur 24h/7j,
  - nombre de restart superviseur/jour,
  - MTTR apres coupure tunnel.
- Network correctness
  - taux de succes DNS local,
  - taux de succes resolution DoT,
  - nombre de leaks DNS detectes (doit rester a 0 en mode DoT).
- Proxy quality
  - requetes HTTP proxy succes/erreur,
  - latence p50/p95,
  - taux de pages cassees (echantillon de sites tests).
- Resource efficiency
  - CPU moyen/p95,
  - RSS memoire moyen/p95,
  - incidents OOM.

---

## 8) Quick wins immediats

1. Corriger la validation healthcheck pour exiger route tun/tap active.
2. Ajouter fallback d'endpoint de test HTTP pour eviter un SPOF externe.
3. Bloquer 53 externe en mode DoT apres bootstrap.
4. Ajouter un test periodique DNS 127.0.0.1 + 5053 expose en metrique.
5. Introduire shellcheck en CI des cette semaine.

---

## 9) Risques si rien n'est fait

- Pannes DNS intermittentes difficiles a reproduire.
- Contournement partiel de la politique anti-leak DNS en mode DoT.
- Regressions silencieuses publiees en image faute de quality gate.
- Degradation perf progressive due au volume de filtres regex.

---

## 10) Definition of Done (fin juillet 2026)

- P0 closes et verifies en test de rupture.
- Pipeline CI bloque toute regression critique.
- Soak test >= 24h vert (ideal 72h).
- Documentation operationnelle a jour (runbook + troubleshooting).
- KPIs stables sur 7 jours consecutifs.
