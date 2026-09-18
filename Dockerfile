# syntax=docker/dockerfile:1
# Cross-compile a fully static musl binary with cargo-zigbuild, ship it FROM scratch.
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/cargo-zigbuild:latest AS builder
ARG TARGETPLATFORM
WORKDIR /src

# Map docker platform -> rust target
RUN case "$TARGETPLATFORM" in \
      "linux/amd64")  echo x86_64-unknown-linux-musl  > /target ;; \
      "linux/arm64")  echo aarch64-unknown-linux-musl > /target ;; \
      *) echo "unsupported platform $TARGETPLATFORM" && exit 1 ;; \
    esac && rustup target add "$(cat /target)"

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo zigbuild --release --locked --target "$(cat /target)" && \
    cp "target/$(cat /target)/release/nano-mockidp" /nano-mockidp

FROM scratch
COPY --from=builder /nano-mockidp /nano-mockidp
USER 65534:65534
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/nano-mockidp"]
