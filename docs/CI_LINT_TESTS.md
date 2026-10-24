# CI / Lint / Tests

Documentation des contrôles qualité automatisés du projet.

## Pipeline CI (`.github/workflows/docker-publish.yml`)

Un workflow unique, `docker-publish.yml`, exécute deux jobs :

### Job `checks` (bloque la publication en cas d'échec)

1. **Syntaxe Bash** — `bash -n` sur tous les fichiers `*.sh` du dépôt
2. **ShellCheck** — `shellcheck -S error` sur tous les scripts + `tests/security_regression.bats`
3. **Tests du parser OpenVPN** — `CODE="$GITHUB_WORKSPACE" bash tests/parse_tests.sh` (autonome : ni root ni réseau)
4. **Tests de régression sécurité** — `bats tests/security_regression.bats` (bloquant)
5. **Suite bats legacy** — `tests/common.bats`, `dns_blocklist.bats`, `dns_runtime.bats`, `dot.bats`, `firewall.bats` — réparée (octobre 2026, backlog Q1 de docs/SECURITY_REVIEW.md) et désormais bloquante

### Job `build-and-push` (après `checks`, hors pull request)

- Build multi-arch (`linux/amd64`, `linux/arm64`) via Buildx/QEMU
- Publication sur **Docker Hub** (`titidnh/openvpn_client_proxy`) : `latest` sur `main`, `X.Y.Z` / `X.Y` / `X` sur les tags `v*`
- Scan **Trivy** (HIGH/CRITICAL) — informationnel (`exit-code 0`) pour l'instant ; à passer en bloquant une fois la baseline établie (docs/SECURITY_REVIEW.md §4.3)

Le `GITHUB_TOKEN` est en lecture seule (`permissions: contents: read`) ; le push Docker Hub utilise ses propres secrets.

## Vérifications locales

### ShellCheck

`.shellcheckrc` ajuste les vérifications au dépôt :

```bash
shellcheck scripts/*.sh lib/*.sh
```

### shfmt

`.shfmtrc` impose l'indentation à 4 espaces :

```bash
shfmt -d scripts/*.sh lib/*.sh       # vérification (dry-run)
shfmt -i 4 -w scripts/*.sh lib/*.sh  # réécriture
```

### BATS

```bash
sudo apt-get install bats       # Debian/Ubuntu
CODE="$PWD" bash tests/parse_tests.sh # tests du parser (sans root)
bats tests/security_regression.bats
bats tests/*.bats               # suite complète (legacy + régression sécurité)
```

### Hook pre-commit

`scripts/pre-commit.sh` exécute ShellCheck sur les fichiers `.sh` stagés :

```bash
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Vue d'ensemble des tests

| Fichier | Contenu | CI |
|---|---|---|
| `tests/parse_tests.sh` | Parsing des `remote` OpenVPN (CRLF, BOM, blocs `<connection>`, `rport`) — autonome | Bloquant |
| `tests/security_regression.bats` | Régressions sécurité | Bloquant |
| `tests/common.bats`, `dns_blocklist.bats`, `dns_runtime.bats`, `dot.bats`, `firewall.bats` | Suite legacy — réparée (octobre 2026) | Bloquant |
