# --- build stage -----------------------------------------------------
FROM rust:1-slim-bookworm AS builder
WORKDIR /build

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src/bin \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > src/bin/gen_sample_pcap.rs \
    && cargo build --release || true

COPY . .
RUN touch src/main.rs src/bin/gen_sample_pcap.rs \
    && cargo build --release

# --- runtime stage -----------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/sentinel ./sentinel
COPY --from=builder /build/target/release/gen-sample-pcap ./gen-sample-pcap
COPY static ./static
COPY sample_pcaps ./sample_pcaps
COPY data ./data

ENV SENTINEL_ADDR=0.0.0.0:8787
EXPOSE 8787

CMD ["./sentinel", "serve"]
