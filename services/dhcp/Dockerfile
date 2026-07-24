FROM rust:1.90-slim AS build
WORKDIR /src

# Cache deps separately from source for faster rebuilds.
COPY Cargo.toml Cargo.lock ./
COPY services/filter/mantis-bundle/Cargo.toml services/filter/mantis-bundle/Cargo.toml
COPY services/filter/mantis-policy/Cargo.toml services/filter/mantis-policy/Cargo.toml
COPY services/filter/mantis-filter/Cargo.toml services/filter/mantis-filter/Cargo.toml
COPY services/dhcp/mantis-dhcp/Cargo.toml services/dhcp/mantis-dhcp/Cargo.toml

COPY proto proto
COPY services/filter services/filter
COPY services/dhcp services/dhcp

RUN cargo build --release -p mantis-dhcp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
# mantis-dhcp parses untrusted DHCP traffic straight off the network and
# needs to bind :67 (privileged) and, when a scope sets `interface`, call
# SO_BINDTODEVICE for per-interface dispatch (server.rs's docs on why —
# note SO_BINDTODEVICE needs CAP_NET_RAW even on a plain UDP socket; that's
# a Linux capability-model quirk, not this binary doing raw-socket packet
# crafting). Both are granted on the binary itself instead of running the
# process as root (the container still needs `cap_add: [NET_BIND_SERVICE,
# NET_RAW]` for these file capabilities to take effect — see docker-compose*.yml).
#
# One image, two binaries: `-p mantis-dhcp` above builds every bin target in
# that package, so mantis-dhcp6 (the DHCPv6 daemon, design.md §22.9) is
# already sitting in target/release alongside mantis-dhcp — no second
# Dockerfile. The container's default ENTRYPOINT is still the v4 binary;
# docker-compose*.yml's `dhcp6` service overrides `entrypoint:` to run the
# v6 one instead. It only needs CAP_NET_BIND_SERVICE (:547) — no SO_BINDTODEVICE
# or ICMP probing on the v6 side yet, so no CAP_NET_RAW for it.
RUN groupadd --system mantis && useradd --system --gid mantis --no-create-home --shell /usr/sbin/nologin mantis
COPY --from=build /src/target/release/mantis-dhcp /usr/local/bin/mantis-dhcp
COPY --from=build /src/target/release/mantis-dhcp6 /usr/local/bin/mantis-dhcp6
RUN setcap cap_net_bind_service,cap_net_raw=+ep /usr/local/bin/mantis-dhcp \
    && setcap cap_net_bind_service=+ep /usr/local/bin/mantis-dhcp6
ENV RUST_LOG=info
USER mantis
ENTRYPOINT ["/usr/local/bin/mantis-dhcp"]
