FROM rust:1-slim-buster AS build

RUN apt-get update && apt-get install -y pkg-config libssl-dev
RUN mkdir -p $HOME/.cargo; echo -e '[net]\ngit-fetch-with-cli = true' > $HOME/.cargo/config.toml
RUN mkdir /build
WORKDIR /build
COPY *.toml .
COPY Cargo.lock .
COPY *.rs .
COPY *.txt .
COPY src src
COPY test-data test-data
RUN cargo build --release
RUN strip target/release/clam-sigutil

FROM debian:buster-slim

RUN apt-get update && apt-get install -y libssl1.1
COPY --from=build /build/target/release/clam-sigutil /bin/clam-sigutil

# Set the working directory to /pwd, expecting the user to mount a volume here
WORKDIR /pwd
