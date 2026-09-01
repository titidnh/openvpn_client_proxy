# Analyse elargie des ameliorations - openvpn_client_proxy

Date: 2026-08-31

## 1. Vue d'ensemble

Ton projet est deja au-dessus de la moyenne sur l'architecture technique:
- kill switch iptables,
- supervision active,
- DNS local,
- mode DoT,
- options Tailscale,
- image Docker multi-arch.

Le principal risque n'est pas la brique VPN. Le risque principal est la compatibilite applicative en mode proxy filtre (cas RTS), puis la fiabilite des validations automatiques avant publication.

## 2. Score par domaine (vue large)

- Reseau / VPN: 8/10
- Securite transport (egress control, kill switch): 8/10
- Proxy/filtrage et compatibilite web: 5/10
- Observabilite / diagnostic: 6/10
- Tests / CI / non-regression: 4/10
- Documentation / coherence docs-code: 6/10
- Portabilite exploitation (Linux vs Windows dev): 6/10
- Maintenabilite long terme: 6/10

## 3. Ameliorations majeures (au-dela du bug RTS)

## A. Strategie produit du proxy (normal vs strict)

Constat:
- Les filtres actifs globalement dans [user.action](user.action#L28), [user.action](user.action#L29), [user.action](user.action#L34) sont tres intrusifs.
- Le blocage de familles video/streaming est explicite dans [default.action](default.action#L397) et [default.action](default.action#L32).

Impact:
- Des sites fonctionnent en VPN seul, mais cassent en VPN+proxy.
- Risque de support recurrent (faux positifs de blocage) qui va augmenter avec le temps.

Action:
- Introduire un vrai mode produit:
  - profil normal (defaut): blocage tracking essentiel, sans filtres JS destructifs,
  - profil strict: profil actuel.
- Ajouter une allowlist runtime pour debloquer un domaine sans rebuild image.

## B. Observabilite operationnelle (debug en incident)

Constat:
- Logs privoxy desactives par defaut dans [privoxy.config](privoxy.config#L22) et [privoxy.config](privoxy.config#L23).
- Healthcheck actuel surtout local, avec test non representatif dans [healthcheck.sh](healthcheck.sh#L73).

Impact:
- Difficile d'expliquer rapidement pourquoi un site casse.
- Le service peut etre "healthy" alors qu'un cas usage utilisateur est casse.

Action:
- Ajouter un mode debug temporaire via variable d'env (ex: DEBUG_PRIVOXY=true).
- Ajouter un script de diagnostic cible (DNS, CONNECT 443, HEAD via proxy, details par host).
- Exposer metriques de reussite proxy par type de test (pas seulement VPN up/down).

## C. CI/CD et qualite avant publish

Constat:
- Le workflow publie sur push main/tag sans gate PR robuste: [docker-publish.yml](.github/workflows/docker-publish.yml#L3), [docker-publish.yml](.github/workflows/docker-publish.yml#L44).
- Le Makefile contient lint/test locaux utiles, mais pas imposes par CI: [Makefile](Makefile#L170), [Makefile](Makefile#L193), [Makefile](Makefile#L213), [Makefile](Makefile#L223).

Impact:
- Une regression filtrage/reseau peut partir en production sans verification comportementale.

Action:
- Ajouter un workflow PR quality-gate:
  - shellcheck,
  - validation compose,
  - build image,
  - smoke test VPN+proxy,
  - test compatibilite (ex: RTS + 3 autres sites de reference),
  - scan securite image (ex: Trivy).
- Garder le workflow publish, mais conditionner le publish au passage des gates.

## D. Securite hardening conteneur

Constat:
- Compose declare cap_add + device, mais pas de defense-in-depth supplementaire: [docker-compose.yml](docker-compose.yml#L58), [docker-compose.yml](docker-compose.yml#L62).
- Proxy expose publiquement par defaut: [docker-compose.yml](docker-compose.yml#L74), [privoxy.config](privoxy.config#L19).

Impact:
- Surface d'attaque inutilement ouverte en dev/prod mal segrege.

Action:
- Proposer deux templates Compose officiels:
  - local securise: bind 127.0.0.1:3128,
  - reseau partage: auth obligatoire + firewall hote.
- Ajouter options conseillees:
  - read_only filesystem (si faisable),
  - tmpfs pour /tmp,
  - no-new-privileges,
  - healthcheck plus strict.

## E. Gouvernance des regles de blocage

Constat:
- default.action est tres volumineux et melange "core stable" et blocs experimentaux.
- Quelques signes de dette/qualite regex dans les filtres (ex sequence brute dans [default.filter](default.filter#L90)).

Impact:
- Chaque ajout augmente le risque de casse et de complexite de debug.

Action:
- Segmenter les regles:
  - core-stable.action,
  - optional-streaming-risk.action,
  - experimental.action.
- Mettre en place un protocole de revue des regles (owner, justification, date, test de non regression).

## F. Coherence documentation / code

Constat:
- Des divergences existent:
  - DNS_SERVER_2 doc vs runtime: [README.md](README.md#L327) vs [Dockerfile](Dockerfile#L73)
  - backoff max doc 60s vs code 120s: [README.md](README.md#L707) vs [start.sh](start.sh#L2647)

Impact:
- Mauvaise interpretation des incidents et de l'exploitation.

Action:
- Process "docs as code": toute modif logique doit mettre a jour README + changelog dans la meme PR.

## G. Portabilite de l'experience dev

Constat:
- Le Makefile utilise encore beaucoup docker-compose (v1) au lieu de docker compose plugin moderne: [Makefile](Makefile#L135), [Makefile](Makefile#L245).

Impact:
- Friction sur environnements recents.

Action:
- Basculer progressivement vers docker compose.
- Garder compat v1 optionnelle via detection automatique.

## 4. Focus RTS: piste la plus probable

Pourquoi RTS casse en VPN+proxy:
- Activation globale de filtres agressifs JS/fingerprint.
- Blocages "video/analytics/session" pouvant toucher des dependances du player.
- Potentiels effets de bord sur consent/auth/CDN.

References utiles:
- [user.action](user.action#L28)
- [user.action](user.action#L29)
- [user.action](user.action#L34)
- [default.action](default.action#L397)
- [default.action](default.action#L32)

## 5. Backlog priorise (30 / 60 / 90 jours)

## 0-30 jours

1. Ajouter profil normal par defaut + strict optionnel.
2. Ajouter allowlist runtime pour domaines sensibles.
3. Corriger healthcheck pour test externe realiste (avec fallback).
4. Aligner README sur la realite du code.
5. Ajouter workflow PR quality gate minimum.

## 31-60 jours

1. Segmenter les fichiers de regles en modules.
2. Ajouter script "diagnose-site" exploitable en incident.
3. Ajouter metriques de compatibilite proxy (connect success, dns success, latency).
4. Harden compose avec profils de securite.

## 61-90 jours

1. Test de charge et latence (normal vs strict).
2. Soak test 24-72h automatisable.
3. Publication d'un runbook incident + SLO/SLA internes.
4. Mise en place d'un cycle de revue trimestriel des regles de blocage.

## 6. Definition de succes

- Plus de cas "VPN seul OK / VPN+proxy KO" sur les sites de reference.
- Taux de succes healthcheck representatif des vrais usages proxy.
- Aucune release image sans quality-gate vert.
- Diminution du temps de diagnostic incident.

## 7. Conclusion

Le projet est deja robuste cote tunnel, firewall et architecture runtime. Pour passer au niveau "production fiable", il faut industrialiser la couche proxy:
- filtrage par profils,
- non-regression en CI,
- observabilite orientee cas reels,
- gouvernance des regles.

C'est la voie la plus efficace pour corriger durablement ton probleme RTS et reduire les regressions futures.
