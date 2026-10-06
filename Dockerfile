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
FROM alpine:3.24 AS tailscale-dl

ARG TARGETARCH
# S6 : version FIGEE + empreinte SHA256 verifiee (les binaires tournent en
# root avec NET_ADMIN). Pour mettre a jour : lire "TarballsVersion" sur
# https://pkgs.tailscale.com/stable/?mode=json puis recopier le contenu de
# https://pkgs.tailscale.com/stable/tailscale_<version>_<arch>.tgz.sha256
ARG TAILSCALE_VERSION=1.102.5
ARG TAILSCALE_SHA256_AMD64=65e6d7f19ad7e1c87d20c2a21e92f38a96795cb897af54b04536590e1c148d12
ARG TAILSCALE_SHA256_ARM64=60d60109e33d097318c66adc1f1b4e78e528fa1c0357e8bfe82af99f21a18b89

RUN apk add --no-cache curl tar \
 && ARCH="${TARGETARCH:-amd64}" \
 && case "${ARCH}" in \
      amd64) SHA="${TAILSCALE_SHA256_AMD64}" ;; \
      arm64) SHA="${TAILSCALE_SHA256_ARM64}" ;; \
      *) echo "Unsupported TARGETARCH=${ARCH} - add its SHA256 build arg" >&2; exit 1 ;; \
    esac \
 && URL="https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${ARCH}.tgz" \
 && echo "Downloading: ${URL}" \
 && curl -fsSL "${URL}" -o tailscale.tgz \
 && echo "${SHA}  tailscale.tgz" | sha256sum -c - \
 && PREFIX=$(tar -tz -f tailscale.tgz | head -1 | cut -d/ -f1) \
 && echo "Tailscale version: ${PREFIX}" \
 && tar -xz -f tailscale.tgz "${PREFIX}/tailscale" "${PREFIX}/tailscaled" \
 && mv "${PREFIX}/tailscale" "${PREFIX}/tailscaled" . \
 && rm -rf tailscale.tgz "${PREFIX}" \
 && chmod 755 tailscale tailscaled

# ===========================================================================
# Stage 2 - Image finale
# ===========================================================================
FROM alpine:3.24

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
    VPN_TYPE="openvpn" \
    OPENVPN_ENABLED="true" \
    WIREGUARD_ENABLED="false" \
    DNS_SERVER_1="94.140.14.14" \
    DNS_SERVER_2="94.140.15.15" \
    PROXY_USER="" \
    PROXY_PASS="" \
    PROXY_PROFILE="normal" \
    ENABLE_DOT=false \
    DOT_DNS_SERVERS="tls://dns.adguard-dns.com" \
    ENABLE_DNSSEC=false \
    DOT_TLS_CERT_BUNDLE="" \
    DOT_IP_REFRESH_INTERVAL=3600 \
    ENABLE_DNS_BLOCKLIST=false \
    DNS_BLOCKLIST_URLS="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" \
    DNS_BLOCKLIST_REFRESH_INTERVAL=86400 \
    DNS_BLOCKLIST_MIN_AGE=3600 \
    DNS_BLOCKLIST_ALLOWLIST="" \
    DNS_SPLIT="" \
    ENABLE_METRICS=false \
    DROP_CAPS=false \
    HEALTHCHECK_IP="9.9.9.9" \
    ROUTE_TEST_IP="9.9.9.9" \
    PROXY_TEST_HOST="connectivitycheck.gstatic.com" \
    PROXY_TEST_URL="http://connectivitycheck.gstatic.com/generate_204" \
    SKIP_HEALTHCHECK_FIRST_MINUTES=2

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
#   - tinyproxy pour l'authentification proxy optionnelle (CONNECT + 407 natifs)
#   - socat pour le serveur de métriques (meilleur que nc pour le fallback)
# ---------------------------------------------------------------------------
RUN apk add --no-cache \
      bash \
      bind-tools \
      ca-certificates \
      curl \
      dnsmasq \
      iptables \
      ip6tables \
      iproute2 \
      netcat-openbsd \
      tinyproxy \
      openvpn \
      privoxy \
      tini \
      unbound \
      libcap \
      socat \
      wireguard-tools \
      wireguard-go

# S'assurer que les répertoires runtime d'unbound existent et sont détenus par l'utilisateur unbound
RUN mkdir -p /var/lib/unbound /etc/unbound \
 && chown -R unbound:unbound /var/lib/unbound /etc/unbound 2>/dev/null || true

# D1/D2 : ancre racine DNSSEC. Le 11 octobre 2026 la zone racine n'est plus
# signee que par KSK-2024 (key tag 38696) ; unbound-anchor d'une image Alpine
# plus ancienne peut ne livrer que 20326. On genere root.key avec unbound-anchor
# (qui embarque 20326) puis on garantit la presence de la nouvelle ancre
# officielle 38696 si elle manque. RFC 5011 ajoutera les ancres futures
# automatiquement tant que root.key reste inscriptible par l'utilisateur
# unbound (chown au runtime, voir lib/dot.sh).
RUN unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true \
 && grep -q 38696 /var/lib/unbound/root.key 2>/dev/null \
    || sed -i '1i . IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16' /var/lib/unbound/root.key 2>/dev/null || true \
 && chown unbound:unbound /var/lib/unbound/root.key \
 && chmod 644 /var/lib/unbound/root.key

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
COPY --chmod=0755 vpn-selector.sh /usr/local/bin/vpn-selector.sh
COPY --chmod=0755 vpn-startup.sh  /usr/local/bin/vpn-startup.sh
COPY --chmod=0755 healthcheck.sh  /usr/local/bin/healthcheck.sh
COPY --chmod=0755 start.sh        /start.sh

# Copier les bibliothèques de fonctions
COPY --chmod=0755 lib/common.sh        /usr/local/lib/common.sh
COPY --chmod=0755 lib/dns_blocklist.sh /usr/local/lib/dns_blocklist.sh
COPY --chmod=0755 lib/firewall.sh     /usr/local/lib/firewall.sh
COPY --chmod=0755 lib/dot.sh          /usr/local/lib/dot.sh
COPY --chmod=0755 lib/dns_runtime.sh  /usr/local/lib/dns_runtime.sh
COPY --chmod=0755 lib/wireguard.sh    /usr/local/lib/wireguard.sh
COPY --chmod=0755 lib/supervisor.sh   /usr/local/lib/supervisor.sh

# Supprimer les retours chariot (pour compatibilité Windows CRLF → LF)
RUN find /usr/local/bin /usr/local/lib /start.sh -type f \( -name '*.sh' -o -name 'start.sh' \) -exec sed -i 's/\r$//' {} \; 2>/dev/null || true

# Copier la configuration Privoxy et les fichiers de filtres
COPY --chown=vpn:vpn \
     privoxy.config default.action default.filter user.action user.filter \
     /etc/privoxy/

# ---------------------------------------------------------------------------
# Volumes et healthcheck
# ---------------------------------------------------------------------------
VOLUME ["/vpn", "/var/lib/tailscale"]

HEALTHCHECK --interval=30s --timeout=20s --start-period=30s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1

# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------
ENTRYPOINT ["/sbin/tini", "--", "/start.sh"]
