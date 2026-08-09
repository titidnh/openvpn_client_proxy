# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr-CH/1.0.0/),
et ce projet adhère à [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-08-09

### Améliorations de la qualité du code

#### Architecture et organisation
- **Création d'une bibliothèque de fonctions communes** (`lib/common.sh`) :
  - Extraction des fonctions dupliquées (`find_vpn_interface`, `vpn_tunnel_ready`, etc.)
  - Centralisation des fonctions de logging, validation, réseau et DNS
  - Réduction significative de la duplication de code entre `start.sh` et `healthcheck.sh`

#### Scripts améliorés

**start.sh** (v2.0.0):
- **Structure modulaire** : Séparation claire en sections (initialisation, firewall, DNS, proxy, Tailscale, supervision)
- **Gestion des PIDs** : Utilisation d'un tableau associatif `SERVICE_PIDS` pour un suivi plus propre
- **Validation d'environnement** : Ajout de fonctions de validation pour les variables d'environnement
- **Meilleure gestion des erreurs** : Utilisation cohérente de `set -euo pipefail`
- **Documentation améliorée** : Commentaires plus détaillés et structurés
- **Fonctions réutilisables** : Extraction des fonctions communes dans `lib/common.sh`
- **Logging structuré** : Amélioration du format JSON avec échappement correct des caractères spéciaux

**healthcheck.sh** (v2.0.0):
- **Utilisation de la bibliothèque commune** : Import de `lib/common.sh` pour éviter la duplication
- **Fonctions modulaires** : Séparation des vérifications en fonctions distinctes
- **Meilleure lisibilité** : Code plus structuré et commenté
- **Gestion des erreurs** : Messages d'erreur plus informatifs

**openvpn.sh** (v2.0.0):
- **Validation des prérequis** : Vérification de l'existence des fichiers et commandes
- **Logging amélioré** : Utilisation de la bibliothèque commune pour le logging
- **Documentation** : Ajout de commentaires et métadonnées

#### Dockerfile amélioré
- **Mise à jour de la base** : Passage à `alpine:3.22` (compatible 2026)
- **Métadonnées enrichies** : Ajout de labels OpenContainers
- **Optimisation** : Meilleure organisation des couches
- **Documentation** : Commentaires plus détaillés

#### docker-compose.yml amélioré
- **Organisation** : Meilleure structuration des sections
- **Documentation** : Commentaires plus clairs et complets
- **Variables par défaut** : Valeurs par défaut mises à jour et documentées

#### Configuration Privoxy
- **privoxy.config** : Configuration plus complète avec options de sécurité avancées
- **user.action** : Documentation améliorée et exemples plus clairs

#### Nouveaux fichiers
- **Makefile** : Ajout de commandes utiles pour la construction, les tests et la gestion
- **.shellcheckrc** : Configuration pour shellcheck avec exclusions justifiées
- **.dockerignore** : Liste complète des fichiers à exclure
- **CHANGELOG.md** : Ce fichier

#### Améliorations de maintenabilité
- **Conventions de nommage** : Noms de variables et fonctions plus cohérents
- **Validation des entrées** : Vérification des types (booléen, nombre, IP, port)
- **Gestion des erreurs** : Messages d'erreur plus informatifs et structurés
- **Documentation** : Commentaires plus détaillés pour les fonctions complexes
- **Modularité** : Séparation du code en modules logiques

#### Compatibilité 2026
- **Alpine 3.23** : Base Docker mise à jour vers une version supportée en 2026
- **DNS par défaut** : AdGuard DNS (94.140.14.14, 94.140.15.15) toujours valide
- **Tailscale** : Support des versions récentes (1.80.3+)
- **Applications** : OpenVPN, Privoxy, dnsmasq, Unbound - toutes compatibles 2026

### Corrections de bugs
- **Duplication de code** : Suppression de `find_vpn_interface` dupliqué
- **Incohérences de style** : Normalisation des guillemets, indentations
- **Gestion des erreurs** : Meilleure gestion des cas d'échec

### Performances
- **Réduction de la taille** : Meilleure organisation du Dockerfile pour le cache
- **Démarrage plus rapide** : Optimisation de l'ordre des opérations

---

## [1.0.0] - 2024-XX-XX

### Version initiale
- Création du projet openvpn_client_proxy
- Implémentation de base du conteneur Docker
- Configuration initiale d'OpenVPN, Privoxy et dnsmasq
- Mise en place du kill switch et de la protection contre les fuites DNS
- Intégration optionnelle de Tailscale

---

[2.0.0]: https://github.com/titidnh/openvpn_client_proxy/compare/v1.0.0...v2.0.0
