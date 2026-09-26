# Plan detaille - Documentation + Maintenabilite sans regressions

Date: 2026-09-26
Last Updated: 2026-09-26

## 📊 Statut Global

**P0 (Urgent - Documentation) : ✅ COMPLET**
- ✅ Commit A: Normalisation EOL (9d90c4c)
- ✅ Commit B: Documentation complète (9d905ae)

**P1 (Qualité - CI/Tests) : ⏳ EN ATTENTE**
- ⏳ CI/lint setup
- ⏳ Tests integration docker
- ⏳ Extraction module dns_blocklist.sh

**P2 (Refactor avancé) : ⏳ EN ATTENTE**
- ⏳ Extraction modules firewall.sh, dot.sh, etc.
- ⏳ Metriques supplementaires
- ⏳ Generation auto README variables

## 1) Etat reel de l'espace non committe

### 1.1 Changements fonctionnels detectes

Les modifications de contenu reelles portent sur 3 fichiers:

- `Dockerfile`
  - Ajout des variables de blocklist DNS:
    - `ENABLE_DNS_BLOCKLIST=false`
    - `DNS_BLOCKLIST_URLS=...`
    - `DNS_BLOCKLIST_REFRESH_INTERVAL=86400`
    - `DNS_BLOCKLIST_MIN_AGE=3600`
    - `DNS_BLOCKLIST_ALLOWLIST=""`

- `lib/common.sh`
  - Initialisation des defaults correspondants dans `init_environment()`.

- `start.sh`
  - Ajout d'un pipeline complet de blocklist DNS:
    - telechargement des listes
    - compilation multi-formats (hosts, adblock, liste brute)
    - garde-fous (taille minimale, cache, fallback)
    - integration `dnsmasq` / `unbound`
    - boucle de refresh periodique
  - Correctifs de stabilite DoT:
    - ajout idempotent des regles firewall port 853
    - ajout immediate des regles au moment de la resolution des IP DoT
    - purge des regles 853 obsoletes au refresh

### 1.2 Fichiers marques modifies mais sans diff de fond : bruit CRLF/LF

Diagnostique:

- 14 fichiers apparaissent en `M` alors qu'ils n'ont que du bruit CRLF/LF
- Git affiche: "LF will be replaced by CRLF the next time Git touches it"
- Seuls 3 fichiers contiennent des modifications fonctionnelles reelles (Dockerfile, lib/common.sh, start.sh)
- Raison probable: config `core.safecrlf` ou `.gitattributes` absent au dernier clone

Consequences:

- Pollution massive des diffs de revue (hard a lire, risk de miss regression).
- Augmente la taille du commit.
- Masque les vrais changements.
- Rend l'historique git peu lisible et peu debuggable.
- Complications potentielles lors de merge/rebase sur branches longues.

Solution: strategie EOL normalisee

1. **Immediat (Commit A - EOL uniquement)**:
   - Creer `.gitattributes` avec regles LF uniformes.
   - Nettoyer l'index: `git rm --cached -r . && git add .`
   - Commit: "chore: normalise line endings (LF) - no functional changes"
   - Resultat: prochain PR sera clean, revues fiables.

2. **Avenir**:
   - Documenter dans CONTRIBUTING.md: "ne jamais melanger commits EOL + logique"
   - Editor config propose LF au dev local (`.editorconfig`).
   - CI detecce tout mix EOL/logique et bloque le merge.

Avant/apres:

- Avant: `git diff` montre 14 fichiers modifies, harder a reviewer.
- Apres: `git diff` ne montre que 3 fichiers avec logique, clair et auditable.

---

## 2) Plan detaille pour ameliorer la documentation

Objectif: aligner la documentation avec les changements reels, rendre l'exploitation plus sure, et reduire le MTTR en incident.

## Phase D1 - Changelog orienté exploitation

**Statut: ✅ COMPLET (Commit B: 9d905ae)**

Actions:

1. ✅ Section `Unreleased` ajoutée en tete de `CHANGELOG.md`.
2. ✅ Documentation distinctement:
   - Feature: blocklist DNS optionnelle.
   - Fix: stabilite DoT lors de rotation d'IP resolvers.
   - Ops: strategie cache/refresh/fallback.
3. ✅ Section "Breaking behavior clarification" indiquant:
   - en mode DoT + blocklist, le comportement DNS attendu est plus strict.

Definition of Done: ✅ Un operateur comprend en moins d'une minute ce qui a change et pourquoi.

## Phase D2 - README: variables d'environnement completes

**Statut: ✅ COMPLET (Commit B: 9d905ae)**

Actions:

1. ✅ Tableau "Environment Variables" complété avec:
   - `ENABLE_DNS_BLOCKLIST`
   - `DNS_BLOCKLIST_URLS`
   - `DNS_BLOCKLIST_REFRESH_INTERVAL`
   - `DNS_BLOCKLIST_MIN_AGE`
   - `DNS_BLOCKLIST_ALLOWLIST`
2. ✅ Chaque variable documentée: valeur par defaut, format, exemple, impact securite/performance.
3. ✅ Exemples compose pour:
   - mode standard (DEFAULT profile)
   - mode DoT (STRICT-FILTERING profile)
   - mode DoT + blocklist (STRICT-FILTERING profile)

Definition of Done: ✅ Les defaults du README matchent exactement ceux du Dockerfile et lib/common.sh.

## Phase D3 - Section dediee "DNS Blocklist"

**Statut: ✅ COMPLET (Commit B: 9d905ae)**

Actions:

1. ✅ Section technique dédiée ajoutée:
   - principe sinkhole DNS avec schéma ASCII
   - formats sources supportes (hosts, adblock, raw)
   - compilation et fichiers générés
   - differences de comportement `dnsmasq` vs `unbound`
2. ✅ Schéma de flux:
   - download -> compile -> include -> reload service DNS
3. ✅ Limites connues documentées:
   - faux positifs possibles
   - dépendance à la qualité des sources externes

Definition of Done: ✅ Un exploitant peut activer la feature sans lire `start.sh`.

## Phase D4 - Runbook troubleshooting

**Statut: ✅ COMPLET (Commit B: 9d905ae)**

Actions:

1. ✅ Runbook incident complet ajouté:
   - echec de telechargement de listes (with fallback cache handling)
   - compilation "anormalement petite" (size validation)
   - domaine legitime bloque (allowlist management)
   - Memory/performance tuning for large blocklists
2. ✅ Diagnostics DNS Blocklist:
   - verification de statut et verification de listes compilées
   - verification de rechargement dnsmasq
   - test de blocage sur domaines connus
3. ✅ Diagnostics DoT:
   - verification de resolution locale
   - verification regles 853
   - validation rechargement `unbound`/`dnsmasq`
4. ✅ Section rollback rapide:
   - desactiver `ENABLE_DNS_BLOCKLIST`
   - redemarrer conteneur

Definition of Done: ✅ La procédure de rollback est executable en moins de 5 minutes.

## Phase D5 - Documentation anti-drift

Actions:

1. Introduire une source de verite pour les variables (fichier central ou script d'extraction).
2. Generer automatiquement la table des variables du README.
3. Ajouter un check CI qui detecte les incoherences doc/code.

Definition of Done:

- impossible de merger une derive de defaults non documentee.

---

## 3) Plan detaille pour la structure projet et la maintenabilite sans regression

Objectif: reduire le couplage et la taille de `start.sh` (3297 lignes), tout en garantissant la stabilite runtime.

## Phase S0 - Hygiene Git et normalisation EOL (Commit A)

**Statut: ✅ COMPLET (Commit A: 6f0ea2f)**

**Objectif**: eliminer le bruit CRLF/LF et etablir des regles claires pour l'avenir.

**Actions concretes**:

1. ✅ `.gitattributes` créé à la racine du repo avec regles LF uniformes.
2. ✅ Index nettoyé: `git rm --cached -r . && git add .`
3. ✅ Validation: aucune modif logique ne s'est glissée.
4. ✅ Commit: "chore: normalize line endings (LF) - no functional changes"

**Risques reduits**: ✅
- ✅ Revues git plus lisibles.
- ✅ Regression detection amelioree (moins de bruit).
- ✅ Historique git non-pollue.
- ✅ CI coherente entre dev/CI/prod.

**Gate de validation**: ✅
- ✅ `git status` affiche 0 fichiers modifies apres ce commit.
- ✅ Prochain commit fonctionnel a une diff clean.

---

## Phase S1 - Modularisation progressive de start.sh

Decoupage cible:

- `lib/firewall.sh`
  - regles iptables/ip6tables, helpers 853
- `lib/dns_blocklist.sh`
  - download/compile/refresh blocklist
- `lib/dot.sh`
  - parse DoT, unbound generation, refresh IP
- `lib/dns_runtime.sh`
  - dnsmasq/unbound bootstrap et bascule
- `lib/supervisor.sh`
  - boucle de supervision, orchestration

Strategie:

1. Extraire en petits lots (1 domaine par PR/commit).
2. Conserver les signatures de fonctions autant que possible.
3. Garder `start.sh` comme orchestrateur mince.

Definition of Done:

- `start.sh` descend sous ~1000 lignes sans changement de comportement observable.

## Phase S2 - Contrat de configuration unique

Actions:

1. Centraliser declarations + defaults + validation des variables.
2. Eviter la duplication entre `Dockerfile`, `lib/common.sh` et README.
3. Ajouter validation stricte:
   - booleens
   - ports
   - URL de blocklist
   - intervals

Definition of Done:

- toute variable invalide echoue au boot avec message explicite.

## Phase S3 - Qualite automatique (CI)

Actions:

1. Lint shell:
   - ShellCheck sur tous scripts `.sh`
2. Format:
   - `shfmt` avec style fixe
3. Tests unitaires shell (`bats`):
   - parser de listes
   - allowlist
   - idempotence iptables 853
4. Tests integration docker:
   - mode DNS standard
   - mode DoT
   - mode DoT + blocklist
   - rotation d'IP DoT simulee

Definition of Done:

- pipeline bloque toute regression critique avant merge.

## Phase S4 - Observabilite orientee operations

Actions:

1. Etendre metriques:
   - dernier refresh blocklist (timestamp)
   - compteur echec download
   - compteur echec compile
   - compteur purge regles 853 obsoletes
2. Uniformiser logs JSON par composant:
   - `dns_blocklist`
   - `dot_refresh`
   - `supervisor`

Definition of Done:

- diagnostic d'incident possible sans exec dans le conteneur.

## Phase S5 - Strategie de deploiement sans regression

Actions:

1. Feature flags conserves par defaut `false`.
2. Deploiement en 3 anneaux:
   - dev local
   - preprod soak test (24-72h)
   - prod
3. Rollback documente et teste regulierement.

Definition of Done:

- rollback execute en moins de 5 minutes, procedure validee.

---

## 4) Ordonnancement recommande des commits - EOL EN PREMIER

⚠️ **CRITIQUE**: Le commit EOL doit etre le premier, isole, AVANT tout changement fonctionnel.

1. **Commit A - normalisation EOL + .gitattributes** *(URGENT - faire en 1er)*
   - Ajouter `.gitattributes`.
   - Nettoyer index: `git rm --cached -r . && git add .`
   - Aucune autre modif.
   - Message: "chore: normalize line endings (LF)"

2. **Commit B - documentation complete** *(une fois A merge)*
   - Mise a jour README (variables blocklist + examples).
   - Mise a jour CHANGELOG (section Unreleased).
   - Exemples docker-compose completes.
   - Runbook troubleshooting.

3. **Commit C - CI/lint/tests** *(apres B, avant refactor)*
   - Ajouter ShellCheck + shfmt config.
   - Ajouter tests bats.
   - Ajouter gates CI.
   - **Sans refactor start.sh**.

4. **Commit D - extraction module blocklist**
   - Creer `lib/dns_blocklist.sh`.
   - Importer dans start.sh.
   - Tests integration validates.

5. **Commit E - extraction modules DoT/firewall**
   - Creer `lib/firewall.sh`, `lib/dot.sh`.
   - Refactor start.sh progressivement.
   - Tests validates.

6. **Commit F - extraction supervisor + nettoyage**
   - Creer `lib/supervisor.sh`.
   - start.sh devient orchestrateur mince.
   - Code review complete.

**Regle d'or**:

- Chaque commit = 1 objectif unique = 1 rollback possible.
- Ne jamais melanger: style + logique + refactor.

---

## 5) Matrice de risques et controles

1. Risque: faux positifs blocklist bloquent des domaines metier.
   - Controle: allowlist + tests de domaines critiques + rollback feature flag.

2. Risque: derive doc/code sur variables.
   - Controle: generation automatique + check CI de coherence.

3. Risque: regression au refactor shell.
   - Controle: tests integration multi-modes + decoupage progressif.

4. Risque: diffs pollues CRLF/LF.
   - Controle: `.gitattributes` + commit separe.

---

## 6) Backlog priorise - EOL EN URGENCE P0

**P0 - URGENT - COMPLET ✅** (Commits: 6f0ea2f, 9d905ae)

0. **Normalisation EOL** ✅ (Commit A: 6f0ea2f)
   - ✅ Créer `.gitattributes` (LF uniform).
   - ✅ `git rm --cached -r . && git add .`
   - ✅ `git commit -m "chore: normalize line endings"`

1. **Changelog Unreleased** ✅ (Commit B: 9d905ae)
   - ✅ Section en tete de `CHANGELOG.md`.
   - ✅ Feature: DNS blocklist.
   - ✅ Fix: stabilite DoT.
   - ✅ Ops: strategie cache/refresh.

2. **README completes** ✅ (Commit B: 9d905ae)
   - ✅ Ajouter table variables blocklist (5 variables documentées).
   - ✅ Ajouter section "DNS Blocklist" (principe + formats + schemas).
   - ✅ Ajouter runbook incident (echec download, faux positifs, allowlist).
   - ✅ Ajouter exemples compose (DEFAULT + STRICT-FILTERING profiles).

3. **Exemple docker-compose.yml** ✅ (Commit B: 9d905ae)
   - ✅ Profil "DEFAULT" (std).
   - ✅ Profil "STRICT-FILTERING" (DoT + blocklist).
   - ✅ Commentaires explicatifs pour basculer entre profils.

**Checkpoint P0: ✅ ATTEINT**
- ✅ `git status` clean
- ✅ README coherent avec code
- ✅ CHANGELOG claire
- ✅ Deux profils de composition clairement documentés

---

**P1 - Qualite + debut refactor**: ⏳ EN ATTENTE

1. **CI/lint setup** ⏳
   - ShellCheck strict.
   - shfmt config.
   - Git hooks optionnel.
   - Temps: ~1h.

2. **Tests integration docker** ⏳
   - Mode DNS std.
   - Mode DoT.
   - Mode DoT + blocklist.
   - Rotation IP DoT.
   - Temps: ~3h.

3. **Extraction module dns_blocklist.sh** ⏳
   - 4 fonctions extraites de start.sh.
   - Tests unitaires bats.
   - Temps: ~2h.

Checkpoint P1: Pipeline CI bloque regression, module blocklist isole et testable.

---

**P2 - Refactor avance + observabilite**: ⏳ EN ATTENTE

1. **Extraction modules firewall.sh, dot.sh, dns_runtime.sh, supervisor.sh** ⏳
   - Decoupage progressif (1 module par PR).
   - Tests d'integration a chaque etape.
   - Temps: ~8h reparties.

2. **Metriques supplementaires** ⏳
   - Timestamp dernier refresh blocklist.
   - Compteurs echec/succes download/compile.
   - Compteurs purge regles 853 obsoletes.
   - Temps: ~2h.

3. **Generation automatique README variables** ⏳
   - Script d'extraction depuis Dockerfile + common.sh.
   - Check CI de coherence.
   - Temps: ~1h.

---

## 7) Criteres de non-regression (gate de release)

Avant toute release:

1. DNS local repond en mode standard et en mode DoT.
2. En mode DoT, aucune fuite DNS externe en port 53 apres bootstrap.
3. Proxy HTTP(S) operationnel avec et sans auth.
4. Rotation IP DoT sans perte de resolution observable.
5. Si blocklist activee, faux positifs gerables via allowlist.
6. Rollback teste (feature flag off + redemarrage).

Si un de ces points echoue: release bloquee.