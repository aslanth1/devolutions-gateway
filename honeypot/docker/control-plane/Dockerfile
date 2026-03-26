FROM rust:1.90-bookworm AS build

WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY devolutions-agent ./devolutions-agent
COPY devolutions-gateway ./devolutions-gateway
COPY devolutions-session ./devolutions-session
COPY honeypot ./honeypot
COPY jetsocat ./jetsocat
COPY testsuite ./testsuite
COPY tools ./tools

RUN cargo build --release -p honeypot-control-plane

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /workspace/target/release/honeypot-control-plane /usr/local/bin/honeypot-control-plane

ENTRYPOINT ["/usr/local/bin/honeypot-control-plane"]
