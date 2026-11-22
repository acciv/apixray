FROM rust:latest AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/apixray /usr/local/bin/apixray
COPY --from=builder /src/target/release/libapixray.so /usr/local/lib/libapixray.so
RUN ldconfig
ENTRYPOINT ["apixray"]
CMD ["help"]
