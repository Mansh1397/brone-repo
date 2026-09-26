# Multi-stage Dockerfile for AWS Nitro Enclave (.eif compilation)
FROM rust:1.75-alpine as builder

RUN apk add --no-libc-dev build-base musl-dev linux-headers gcc git

WORKDIR /usr/src/brone-enclave

COPY Cargo.toml ./
COPY src ./src

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest

WORKDIR /app
COPY --from=builder /usr/src/brone-enclave/target/x86_64-unknown-linux-musl/release/brone-enclave /app/brone-enclave

CMD ["/app/brone-enclave"]
