FROM rust:1.75-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/blueeconomy-waterway-safety /blueeconomy-waterway-safety
USER nonroot:nonroot
ENTRYPOINT ["/blueeconomy-waterway-safety"]
