FROM rust:1-slim-bookworm AS build

RUN apt-get update && \
      apt-get install -y --no-install-recommends pkg-config libssl-dev && \
      rm -rf /var/lib/apt/lists/* && \
      mkdir -p "$HOME/.cargo" && \
      printf '[net]\ngit-fetch-with-cli = true\n' > "$HOME/.cargo/config.toml" && \
      mkdir /build
WORKDIR /build
COPY *.toml .
COPY Cargo.lock .
COPY *.rs .
COPY *.txt .
COPY src src
COPY test-data test-data
RUN cargo build --release
RUN strip target/release/clam-sigutil

FROM debian:bookworm-slim

RUN apt-get update && \
      apt-get install -y --no-install-recommends libssl3 && \
      rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/clam-sigutil /bin/clam-sigutil

# Set the working directory to /pwd, expecting the user to mount a volume here
WORKDIR /pwd
