FROM node:lts-alpine AS frontend
RUN apk --no-cache add git
WORKDIR /usr/src/app
COPY . .
RUN npm ci --legacy-peer-deps
RUN npm run build

FROM rust:alpine AS backend
WORKDIR /home/rust/src
RUN apk --no-cache add musl-dev openssl-dev
RUN rustup component add rustfmt
COPY . .
COPY --from=frontend /usr/src/app/build build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/home/rust/src/target \
    cargo build --release --bin sshx-server --features embedded && \
    cp target/release/sshx-server /usr/local/bin

FROM alpine:latest
WORKDIR /root
COPY --from=backend /usr/local/bin/sshx-server .
CMD ["./sshx-server", "--listen", "0.0.0.0", "--port", "8051"]
