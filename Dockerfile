FROM node:22-slim AS ui-builder
RUN corepack enable
WORKDIR /ui
COPY ui/package.json ui/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY ui/ .
RUN pnpm build

FROM rust:1.94 AS builder
RUN apt-get update && apt-get install -y cmake libcurl4-openssl-dev pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --locked --release --bin peat-gateway --features full

FROM registry.access.redhat.com/ubi9/ubi:latest AS ubi-builder
RUN dnf install -y gcc gcc-c++ cmake make openssl-devel pkg-config curl-devel && dnf clean all
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.94.0
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /build
COPY . .
RUN cargo build --locked --release --bin peat-gateway --features full

FROM cgr.dev/chainguard/glibc-dynamic:latest AS chainguard
# chainguard/glibc-dynamic ships only glibc; copy the shared libs the binary
# needs at runtime. Glob handles both x86_64 and aarch64 lib paths.
COPY --from=builder /usr/lib/*/libssl.so.3 /usr/lib/
COPY --from=builder /usr/lib/*/libcrypto.so.3 /usr/lib/
COPY --from=builder /usr/lib/*/libz.so.1 /usr/lib/
COPY --from=builder /usr/lib/*/libzstd.so.1 /usr/lib/
COPY --from=builder /build/target/release/peat-gateway /usr/local/bin/
COPY --from=ui-builder /ui/build /app/ui/build
ENV PEAT_UI_DIR=/app/ui/build
EXPOSE 8080 11204 11205
ENTRYPOINT ["peat-gateway"]

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS ubi
RUN microdnf install -y shadow-utils openssl-libs && microdnf clean all && \
    groupadd -r peat && useradd -r -g peat -d /var/lib/peat-gateway -s /sbin/nologin peat && \
    mkdir -p /var/lib/peat-gateway && chown peat:peat /var/lib/peat-gateway
COPY --from=ubi-builder /build/target/release/peat-gateway /usr/local/bin/
COPY --from=ui-builder /ui/build /app/ui/build
ENV PEAT_UI_DIR=/app/ui/build
EXPOSE 8080 11204 11205
USER peat
ENV PEAT_GATEWAY_DATA_DIR=/var/lib/peat-gateway
ENTRYPOINT ["peat-gateway"]
