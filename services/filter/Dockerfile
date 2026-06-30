FROM rust:1.90-slim AS build
WORKDIR /src

# Cache deps separately from source for faster rebuilds.
COPY Cargo.toml Cargo.lock ./
COPY services/filter/aegis-bundle/Cargo.toml services/filter/aegis-bundle/Cargo.toml
COPY services/filter/aegis-policy/Cargo.toml services/filter/aegis-policy/Cargo.toml
COPY services/filter/aegis-filter/Cargo.toml services/filter/aegis-filter/Cargo.toml

COPY proto proto
COPY services/filter services/filter

RUN cargo build --release -p aegis-filter

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/aegis-filter /usr/local/bin/aegis-filter
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/aegis-filter"]
