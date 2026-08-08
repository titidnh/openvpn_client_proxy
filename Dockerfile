# ===========================================================================
# Dockerfile pour openvpn_client_proxy
# 
# Image Docker légère avec :
# - OpenVPN client
# - HTTP proxy (Privoxy)
# - Local DNS resolver (dnsmasq)
# - DNS-over-TLS (Unbound)
# - Optionnellement Tailscale
# 
# Auteur: Vibe Code (amélioration 2026)
# Licence: MIT
# Version: 2.0.0
# ===========================================================================

# ===========================================================================
# Stage 1 - Téléchargement des binaires Tailscale
# ===========================================================================
# Download seulement les deux binaires dont nous avons besoin (tailscale + tailscaled).
# L'utilisation d'un stage dédié évite d'inclure l'outil de construction dans
# l'image finale et permet à BuildKit de mettre en cache la couche de téléchargement
# indépendamment.
# ===========================================================================
FROM alpine:3.22 AS tailscale-dl

ARG TARGETARCH
# TAILSCALE_VERSION peut être figé à l'époque de la construction: --build-arg TAILSCALE_VERSION=1.80.3
# Si laissé vide, la dernière version stable est récupérée automatiquement.
ARG TAILSCALE_VERSION=""

RUN apk add --no-cache curl tar \
 && ARCH="${TARGETARCH:-amd64}" \
 && if [ -n "${TAILSCALE_VERSION}" ]; then \
      URL="https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${ARCH}.tgz"; \
    else \
      URL="https://pkgs.tailscale.com/stable/tailscale_latest_${ARCH}.tgz"; \
    fi \
 && echo "Downloading: ${URL}" \
 && curl -fsSL "${URL}" -o tailscale.tgz \
 && PREFIX=$(tar -tz -f tailscale.tgz | head -1 | cut -d/ -f1) \
 && echo "Tailscale version: ${PREFIX}" \
 && tar -xz -f tailscale.tgz "${PREFIX}/tailscale" "${PREFIX}/tailscaled" \
 && mv "${PREFIX}/tailscale" "${PREFIX}/tailscaled" . \
 && rm -rf tailscale.tgz "${PREFIX}" \
 && chmod 755 tailscale tailscaled

# ===========================================================================
# Stage 2 - Image finale
# ===========================================================================
FROM alpine:3.22

# ---------------------------------------------------------------------------
# Métadonnées de l'image
# ---------------------------------------------------------------------------
LABEL org.opencontainers.image.title="openvpn-client-proxy" \
      org.opencontainers.image.description="Lightweight Docker container running an OpenVPN client, an HTTP proxy (Privoxy), and a local DNS resolver (dnsmasq) — featuring a network kill switch, DNS leak protection, optional proxy authentication, and optional Tailscale integration." \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.authors="titidnh" \
      org.opencontainers.image.url="https://github.com/titidnh/openvpn_client_proxy" \
      org.opencontainers.image.licenses="MIT"

# ---------------------------------------------------------------------------
# Variables d'environnement par défaut
# ---------------------------------------------------------------------------
ENV ENABLE_TAILSCALE=false \
    TAILSCALE_AUTHKEY="" \
    TAILSCALE_FLAGS="" \
    TAILSCALE_ACCEPT_ROUTES=false \
    TAILSCALE_HOSTNAME="openvpn-client-proxy" \
    TAILSCALE_ADVERTISE_EXIT_NODE=false \
    
    # DNS - AdGuard DNS (toujours valide en 2026)
    DNS_SERVER_1="94.140.14.14" \
    DNS_SERVER_2="94.140.15.15" \
    
    # Proxy auth
    PROXY_USER="" \
    PROXY_PASS="" \
    
    # DNS-over-TLS
    ENABLE_DOT=false \
    DOT_DNS_SERVERS="tls://dns.adguard-dns.com" \
    ENABLE_DNSSEC=false \
    DOT_TLS_CERT_BUNDLE="" \
    DOT_IP_REFRESH_INTERVAL=3600 \
    DNS_SPLIT="" \
    
    # Métriques
    ENABLE_METRICS=false \
    
    # Sécurité
    DROP_CAPS=false \
    
    # Healthcheck
    HEALTHCHECK_IP="9.9.9.9" \
    ROUTE_TEST_IP="9.9.9.9" \
    PROXY_TEST_HOST="connectivitycheck.gstatic.com" \
    PROXY_TEST_URL="http://connectivitycheck.gstatic.com/generate_204" \
    SKIP_HEALTHCHECK_FIRST_MINUTES=2 \

# ---------------------------------------------------------------------------
# Utilisateur système
# Alpine utilise addgroup / adduser au lieu de groupadd / useradd
# ---------------------------------------------------------------------------
RUN addgroup -S vpn && adduser -S -G vpn -H -s /sbin/nologin vpn

# ---------------------------------------------------------------------------
# Paquets runtime
# Notes:
#   - busybox (inclus dans Alpine base) fournit nslookup → pas besoin de dnsutils
#   - tini est dans le repo principal d'Alpine
#   - ip6tables est regroupé avec iptables sur Alpine
#   - nginx + apache2-utils pour l'authentification proxy optionnelle
#   - socat pour le serveur de métriques (meilleur que nc pour le fallback)
# ---------------------------------------------------------------------------
RUN apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      dnsmasq \
      iptables \
      ip6tables \
      iproute2 \
      netcat-openbsd \
      nginx \
      apache2-utils \
      openvpn \
      privoxy \
      tini \
      unbound \
      libcap \
      python3 \
      socat

# S'assurer que les répertoires runtime d'unbound existent et sont détenus par l'utilisateur unbound
RUN mkdir -p /var/lib/unbound /etc/unbound \
 && chown -R unbound:unbound /var/lib/unbound /etc/unbound 2>/dev/null || true

# ---------------------------------------------------------------------------
# Binaires Tailscale depuis le stage 1
# ---------------------------------------------------------------------------
COPY --from=tailscale-dl /tailscale  /usr/local/bin/tailscale
COPY --from=tailscale-dl /tailscaled /usr/local/bin/tailscaled

# ---------------------------------------------------------------------------
# Scripts d'application et configuration Privoxy
# ---------------------------------------------------------------------------
# Créer le répertoire lib
RUN mkdir -p /usr/local/lib

# Copier les scripts avec les bonnes permissions
COPY --chmod=0755 openvpn.sh      /usr/local/bin/openvpn.sh
COPY --chmod=0755 healthcheck.sh  /usr/local/bin/healthcheck.sh
COPY --chmod=0755 start.sh        /start.sh

# Copier la bibliothèque de fonctions communes
COPY --chmod=0755 lib/common.sh   /usr/local/lib/common.sh

# Supprimer les retours chariot (pour compatibilité Windows)
RUN sed -i 's/\r//' /start.sh /usr/local/bin/openvpn.sh /usr/local/bin/healthcheck.sh

# Copier la configuration Privoxy et les fichiers de filtres
COPY --chown=vpn:vpn \
     privoxy.config default.action default.filter user.action user.filter \
     /etc/privoxy/

# ---------------------------------------------------------------------------
# Volumes et healthcheck
# ---------------------------------------------------------------------------
VOLUME ["/vpn", "/var/lib/tailscale"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1

# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------
ENTRYPOINT ["/sbin/tini", "--", "/start.sh"]
