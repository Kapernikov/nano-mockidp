# syntax=docker/dockerfile:1
# Build a fully static binary with musl, ship it FROM scratch.
FROM --platform=$BUILDPLATFORM rust:1-alpine AS builder
ARG TARGETPLATFORM
RUN apk add --no-cache musl-dev perl make
WORKDIR /src

# Map docker platform -> rust target
RUN case "$TARGETPLATFORM" in \
      "linux/amd64")  echo x86_64-unknown-linux-musl  > /target ;; \
      "linux/arm64")  echo aarch64-unknown-linux-musl > /target ;; \
      *) echo "unsupported platform $TARGETPLATFORM" && exit 1 ;; \
    esac && rustup target add "$(cat /target)"

# Cross linker for arm64 when building on amd64 (and vice versa).
RUN if [ "$(cat /target)" = "aarch64-unknown-linux-musl" ] && [ "$(uname -m)" != "aarch64" ]; then \
      wget -qO- https://musl.cc/aarch64-linux-musl-cross.tgz | tar -xz -C /opt && \
      printf '[target.aarch64-unknown-linux-musl]\nlinker = "/opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"\n' > /usr/local/cargo/config.toml; \
    fi

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release --locked --target "$(cat /target)" && \
    cp "target/$(cat /target)/release/nano-mockidp" /nano-mockidp

FROM scratch
COPY --from=builder /nano-mockidp /nano-mockidp
USER 65534:65534
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/nano-mockidp"]
