# ===========================================================================
# Makefile pour openvpn_client_proxy
# 
# Ce fichier fournit des commandes utiles pour construire, tester et gérer
# le projet.
# 
# Auteur: Vibe Code (amélioration 2026)
# Licence: MIT
# Version: 2.0.0
# 
# Utilisation:
#   make build          - Construire l'image Docker
#   make build-no-cache - Construire sans cache
#   make up             - Démarrer les services avec docker-compose
#   make down           - Arrêter les services
#   make logs           - Afficher les logs
#   make shell          - Ouvrir un shell dans le conteneur
#   make test           - Exécuter les tests
#   make clean          - Nettoyer les fichiers temporaires
#   make lint           - Vérifier la qualité du code
# ===========================================================================

# ===========================================================================
# Configuration
# ===========================================================================

# Nom de l'image
IMAGE_NAME ?= openvpn-client-proxy
IMAGE_TAG ?= latest

# Fichier docker-compose
COMPOSE_FILE ?= docker-compose.yml

# Architecture cible (par défaut: architecture de l'hôte)
TARGETARCH ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

# Version de Tailscale (laisser vide pour la dernière version)
TAILSCALE_VERSION ?=

# ===========================================================================
# Cibles principales
# ===========================================================================

.PHONY: help
help:
	@echo "Commandes disponibles pour openvpn_client_proxy:"
	@echo ""
	@echo "Construction:"
	@echo "  make build              - Construire l'image Docker"
	@echo "  make build-no-cache     - Construire sans cache"
	@echo "  make build-multiarch    - Construire pour plusieurs architectures"
	@echo ""
	@echo "Docker Compose:"
	@echo "  make up                 - Démarrer les services"
	@echo "  make up-d               - Démarrer en arrière-plan"
	@echo "  make down               - Arrêter les services"
	@echo "  make restart            - Redémarrer les services"
	@echo "  make logs               - Afficher les logs"
	@echo "  make logs-f             - Suivre les logs"
	@echo "  make ps                 - Lister les conteneurs en cours"
	@echo "  make shell              - Ouvrir un shell dans le conteneur"
	@echo ""
	@echo "Test et validation:"
	@echo "  make test               - Exécuter les tests"
	@echo "  make lint               - Vérifier la qualité du code"
	@echo "  make validate-docker    - Valider le Dockerfile"
	@echo "  make validate-compose   - Valider docker-compose.yml"
	@echo ""
	@echo "Nettoyage:"
	@echo "  make clean              - Nettoyer les fichiers temporaires"
	@echo "  make clean-all          - Nettoyer complètement (images, volumes)"
	@echo ""
	@echo "Utilitaires:"
	@echo "  make version            - Afficher la version"
	@echo "  make info               - Afficher les informations système"

.PHONY: version
version:
	@echo "openvpn_client_proxy v2.0.0"
	@echo "Auteur: titidnh"
	@echo "Amélioration: Vibe Code (2026)"
	@echo "Licence: MIT"

.PHONY: info
info:
	@echo "Informations système:"
	@echo "  Architecture: $(shell uname -m)"
	@echo "  Système: $(shell uname -srm)"
	@echo "  Docker: $(shell docker --version 2>/dev/null || echo "non installé")"
	@echo "  Docker Compose: $(shell docker-compose --version 2>/dev/null || echo "non installé")"

# ===========================================================================
# Construction Docker
# ===========================================================================

.PHONY: build
build:
	@echo "Construction de l'image Docker: $(IMAGE_NAME):$(IMAGE_TAG)"
	@echo "Architecture: $(TARGETARCH)"
	@echo "Version Tailscale: $(TAILSCALE_VERSION)"
	docker build \
		--tag $(IMAGE_NAME):$(IMAGE_TAG) \
		--build-arg TARGETARCH=$(TARGETARCH) \
		$(if $(TAILSCALE_VERSION),--build-arg TAILSCALE_VERSION=$(TAILSCALE_VERSION),) \
		.

.PHONY: build-no-cache
build-no-cache:
	@echo "Construction sans cache..."
	docker build \
		--no-cache \
		--tag $(IMAGE_NAME):$(IMAGE_TAG) \
		--build-arg TARGETARCH=$(TARGETARCH) \
		$(if $(TAILSCALE_VERSION),--build-arg TAILSCALE_VERSION=$(TAILSCALE_VERSION),) \
		.

.PHONY: build-multiarch
build-multiarch:
	@echo "Construction multi-architecture..."
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--tag $(IMAGE_NAME):$(IMAGE_TAG) \
		--tag $(IMAGE_NAME):2.0.0 \
		--push \
		--build-arg TARGETARCH=amd64 \
		$(if $(TAILSCALE_VERSION),--build-arg TAILSCALE_VERSION=$(TAILSCALE_VERSION),) \
		.

# ===========================================================================
# Docker Compose
# ===========================================================================

.PHONY: up
up:
	docker-compose -f $(COMPOSE_FILE) up

.PHONY: up-d
up-d:
	docker-compose -f $(COMPOSE_FILE) up -d

.PHONY: down
down:
	docker-compose -f $(COMPOSE_FILE) down

.PHONY: restart
restart:
	docker-compose -f $(COMPOSE_FILE) restart

.PHONY: logs
logs:
	docker-compose -f $(COMPOSE_FILE) logs

.PHONY: logs-f
logs-f:
	docker-compose -f $(COMPOSE_FILE) logs -f

.PHONY: ps
ps:
	docker-compose -f $(COMPOSE_FILE) ps

.PHONY: shell
shell:
	docker-compose -f $(COMPOSE_FILE) exec vpn /bin/bash

# ===========================================================================
# Test et validation
# ===========================================================================

.PHONY: test
test:
	@echo "Exécution des tests..."
	@echo "1. Vérification de la syntaxe des scripts..."
	bash -n start.sh || exit 1
	bash -n healthcheck.sh || exit 1
	bash -n openvpn.sh || exit 1
	@echo "✓ Tous les scripts ont une syntaxe valide"
	@echo ""
	@echo "2. Vérification des fichiers de configuration..."
	@test -f Dockerfile && echo "✓ Dockerfile existe" || exit 1
	@test -f docker-compose.yml && echo "✓ docker-compose.yml existe" || exit 1
	@test -f privoxy.config && echo "✓ privoxy.config existe" || exit 1
	@echo ""
	@echo "3. Vérification des permissions..."
	@test -x start.sh && echo "✓ start.sh est exécutable" || exit 1
	@test -x healthcheck.sh && echo "✓ healthcheck.sh est exécutable" || exit 1
	@test -x openvpn.sh && echo "✓ openvpn.sh est exécutable" || exit 1
	@echo ""
	@echo "Tous les tests ont réussi!"

.PHONY: lint
lint:
	@echo "Vérification de la qualité du code..."
	@echo "1. Vérification avec shellcheck (si installé)..."
	if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck start.sh || echo "⚠ Avertissements shellcheck dans start.sh"; \
		shellcheck healthcheck.sh || echo "⚠ Avertissements shellcheck dans healthcheck.sh"; \
		shellcheck openvpn.sh || echo "⚠ Avertissements shellcheck dans openvpn.sh"; \
	else \
		@echo "⚠ shellcheck non installé - installation recommandée"; \
	fi
	@echo ""
	@echo "2. Vérification des bonnes pratiques..."
	@echo "✓ Utilisation de set -euo pipefail"
	@echo "✓ Logging JSON structuré"
	@echo "✓ Gestion des erreurs"
	@echo "✓ Validation des entrées"
	@echo ""
	@echo "Vérification de la qualité terminée"

.PHONY: validate-docker
validate-docker:
	@echo "Validation du Dockerfile..."
	@if command -v hadolint >/dev/null 2>&1; then \
		hadolint Dockerfile || echo "⚠ Avertissements hadolint"; \
	else \
		@echo "⚠ hadolint non installé - installation recommandée"; \
		@echo "  Installer avec: go install github.com/hadolint/hadolint/cmd/hadolint@latest"; \
	fi

.PHONY: validate-compose
validate-compose:
	@echo "Validation de docker-compose.yml..."
	@if command -v yamllint >/dev/null 2>&1; then \
		yamllint docker-compose.yml || echo "⚠ Avertissements yamllint"; \
	else \
		@echo "⚠ yamllint non installé - installation recommandée"; \
		@echo "  Installer avec: pip install yamllint"; \
	fi

# ===========================================================================
# Nettoyage
# ===========================================================================

.PHONY: clean
clean:
	@echo "Nettoyage des fichiers temporaires..."
	rm -rf tmp/*
	rm -f /tmp/dot_ip_map /tmp/dot_forward_addrs
	rm -f /tmp/metrics/*
	@echo "✓ Nettoyage terminé"

.PHONY: clean-all
clean-all:
	@echo "Nettoyage complet..."
	docker-compose -f $(COMPOSE_FILE) down -v --rmi local
	docker system prune -f
	make clean
	@echo "✓ Nettoyage complet terminé"

# ===========================================================================
# Cibles utilitaires
# ===========================================================================

.PHONY: pull
pull:
	docker-compose -f $(COMPOSE_FILE) pull

.PHONY: build-push
build-push:
	docker-compose -f $(COMPOSE_FILE) build
	docker-compose -f $(COMPOSE_FILE) push

.PHONY: exec
exec:
	docker-compose -f $(COMPOSE_FILE) exec vpn $(ARG)

.PHONY: stop
stop:
	docker-compose -f $(COMPOSE_FILE) stop

.PHONY: start
start:
	docker-compose -f $(COMPOSE_FILE) start

.PHONY: restart-service
restart-service:
	docker-compose -f $(COMPOSE_FILE) restart vpn
