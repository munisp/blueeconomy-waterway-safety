# Not 1.75 (this crate's prior floor) or even 1.85: opentelemetry-otlp's
# tonic backend transitively needs edition2024 (stable since 1.85), and its
# own icu_* deps need 1.88 on top of that - confirmed by chasing one MSRV
# bump into the next. Floating on `1` avoids re-chasing this every time a
# transitive dep bumps its own floor again.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/blueeconomy-waterway-safety /blueeconomy-waterway-safety
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/blueeconomy-waterway-safety"]
CMD ["--serve"]
