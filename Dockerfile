FROM rust:1-slim-buster AS build

    RUN mkdir -p $HOME/.cargo; echo -e '[net]\ngit-fetch-with-cli = true' > $HOME/.cargo/config.toml
    RUN mkdir /build
    WORKDIR /build
    COPY *.toml .
    COPY *.rs .
    COPY src src
    COPY test-data test-data
    RUN cargo update
    RUN cargo build --release
    RUN strip target/release/clam-sigutil

FROM debian:buster-slim

    COPY --from=build /build/target/release/clam-sigutil /bin/clam-sigutil
    ENTRYPOINT ["/bin/clam-sigutil"]
