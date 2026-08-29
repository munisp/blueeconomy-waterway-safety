# syntax=docker/dockerfile:1
# Base image: rust:1.85-bookworm manifest-list digest, retrieved 2026-08-29 from the
# Docker Hub registry API through two independent registry mirrors (dockerproxy.net
# and docker.1ms.run, which returned identical digests) because auth.docker.io was
# unreachable from the authoring environment. Verify or refresh with:
#   docker buildx imagetools inspect rust:1.85-bookworm
# The build base moved from 1.75 to 1.85 because the locked kafka-transport
# tree (openssl-sys 0.9.117) requires rustc 1.80+; 1.75 remains the crate's
# declared MSRV for the default-feature build, the release image is simply
# compiled with a newer toolchain.
FROM rust:1.85-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Build both binaries. The gateway needs one compiled uplink transport or it
# fails closed at startup with transport_unavailable; kafka-transport is the
# pinned fallback with the small dependency tree (fluvio-transport pulls the
# full Fluvio client stack).
RUN cargo build --release --locked --bins --features kafka-transport

# Base image: gcr.io/distroless/cc-debian12:nonroot manifest-index digest, retrieved
# 2026-08-27 via the gcr.io mirror gcr.m.daocloud.io (gcr.io was unreachable from the
# authoring environment). Verify or refresh with:
#   docker buildx imagetools inspect gcr.io/distroless/cc-debian12:nonroot
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
# The network gateway is the deployed workload and is the image entrypoint.
# The CLI validator stays in the image as an auxiliary binary:
#   docker run --entrypoint /blueeconomy-waterway-safety <image> <telemetry.json>
COPY --from=build /src/target/release/gateway /gateway
COPY --from=build /src/target/release/blueeconomy-waterway-safety /blueeconomy-waterway-safety
USER nonroot:nonroot
# The gateway is configured environment-only and fails closed (exit 2) when
# GATEWAY_ID, VESSEL_DEVICE_ID, JOURNAL_DIR or UPLINK_TRANSPORT are missing,
# and (exit 1) when the provenance signing key or the uplink is unavailable.
# AIS_LISTEN_ADDR / SENSOR_LISTEN_ADDR default to loopback; publish ports only
# after setting them to a routable address such as 0.0.0.0:10110 / 0.0.0.0:10111.
ENTRYPOINT ["/gateway"]
