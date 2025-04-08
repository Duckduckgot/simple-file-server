FROM rust:latest as rust

LABEL org.opencontainers.image.source https://github.com/Duckduckgot/simple-file-server

WORKDIR /src
RUN apt-get update && apt-get install -y musl-dev musl-tools clang build-essential
RUN rustup target add x86_64-unknown-linux-musl
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM debian:buster-slim
RUN useradd -ms /bin/bash -u 1001 kali
RUN mkdir -p /files && chown kali:kali /files
WORKDIR /home/kali/simple-file-server
COPY . .
COPY --from=rust /src/target/release/simple-file-server .
USER kali
CMD [ "/home/kali/simple-file-server/simple-file-server" ]
