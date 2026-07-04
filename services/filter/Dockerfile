FROM rust:1.90-slim AS build
WORKDIR /src

# Cache deps separately from source for faster rebuilds.
COPY Cargo.toml Cargo.lock ./
COPY services/filter/mantis-bundle/Cargo.toml services/filter/mantis-bundle/Cargo.toml
COPY services/filter/mantis-policy/Cargo.toml services/filter/mantis-policy/Cargo.toml
COPY services/filter/mantis-filter/Cargo.toml services/filter/mantis-filter/Cargo.toml

COPY proto proto
COPY services/filter services/filter

RUN cargo build --release -p mantis-filter

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/mantis-filter /usr/local/bin/mantis-filter
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/mantis-filter"]
