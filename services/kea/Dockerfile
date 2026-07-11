FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    jq \
    postgresql-client \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Cloudsmith's bootstrap script is generated per-distro/version server-side,
# so there's no fixed release artifact to pin a checksum against — but
# piping curl straight into bash means a failed/truncated download (or a
# MITM'd/downgraded connection) executes whatever bytes arrive, silently, as
# root. Download to a file first so a bad response fails loudly instead;
# --proto/--tlsv1.2 rule out a protocol downgrade.
RUN kea_setup_script="$(mktemp)" \
    && curl -fsSL --proto '=https' --tlsv1.2 \
        'https://dl.cloudsmith.io/public/isc/kea-3-0/setup.deb.sh' \
        -o "$kea_setup_script" \
    && [ -s "$kea_setup_script" ] \
    && head -c2 "$kea_setup_script" | grep -q '^#!' \
    && bash "$kea_setup_script" \
    && rm -f "$kea_setup_script" \
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
