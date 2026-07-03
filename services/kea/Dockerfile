FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    kea-dhcp4-server \
    kea-dhcp6-server \
    kea-ctrl-agent \
    kea-admin \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/kea /etc/kea

COPY kea-dhcp4.conf /etc/kea/kea-dhcp4.conf
COPY kea-dhcp6.conf /etc/kea/kea-dhcp6.conf
COPY kea-ctrl-agent.conf /etc/kea/kea-ctrl-agent.conf
COPY aegis-ddns-bridge.sh /usr/local/bin/aegis-ddns-bridge.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/aegis-ddns-bridge.sh

EXPOSE 8080
EXPOSE 67/udp
EXPOSE 547/udp

ENTRYPOINT ["/entrypoint.sh"]
