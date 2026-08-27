# syntax=docker/dockerfile:1
# Base image: rust:1.75-bookworm manifest-list digest, retrieved 2026-08-27 from the
# Docker Hub registry API through two independent registry mirrors (dockerproxy.net
# and docker.1ms.run, which returned identical digests) because auth.docker.io was
# unreachable from the authoring environment. Verify or refresh with:
#   docker buildx imagetools inspect rust:1.75-bookworm
FROM rust:1.75-bookworm@sha256:87f3b2f93b82995443a1a558c234212dafe79cfdc3af956539610560369ddcd0 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Base image: gcr.io/distroless/cc-debian12:nonroot manifest-index digest, retrieved
# 2026-08-27 via the gcr.io mirror gcr.m.daocloud.io (gcr.io was unreachable from the
# authoring environment). Verify or refresh with:
#   docker buildx imagetools inspect gcr.io/distroless/cc-debian12:nonroot
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/blueeconomy-waterway-safety /blueeconomy-waterway-safety
USER nonroot:nonroot
ENTRYPOINT ["/blueeconomy-waterway-safety"]
