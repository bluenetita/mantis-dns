FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    postgresql-client \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

RUN curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-3-0/setup.deb.sh' | bash \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        isc-kea-dhcp4 \
        isc-kea-dhcp6 \
        isc-kea-admin \
        isc-kea-hooks \
        isc-kea-pgsql \
    && rm -rf /var/lib/apt/lists/*

RUN hooks_dir="$(dirname "$(find /usr/lib -name 'libdhcp_lease_cmds.so' | head -1)")" \
    && mkdir -p /usr/lib/kea \
    && ln -s "$hooks_dir" /usr/lib/kea/hooks

RUN mkdir -p /etc/kea

COPY kea-dhcp4.conf /etc/kea/kea-dhcp4.conf
COPY kea-dhcp6.conf /etc/kea/kea-dhcp6.conf
COPY mantis-ddns-bridge.sh /usr/share/kea/scripts/mantis-ddns-bridge.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/share/kea/scripts/mantis-ddns-bridge.sh

EXPOSE 8004
EXPOSE 8006
EXPOSE 67/udp
EXPOSE 547/udp

ENTRYPOINT ["/entrypoint.sh"]
