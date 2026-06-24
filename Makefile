BINARY      := vapx-scan
MUSL_TARGET := x86_64-unknown-linux-musl
DIST        := dist

# Raspberry Pi / ARM targets (built with `cross`, Docker required):
#   arm64   aarch64-unknown-linux-musl        Pi 3/4/5 (64-bit OS)
#   armv7   armv7-unknown-linux-musleabihf    Pi 2/3/4 (32-bit OS)
#   armv6   arm-unknown-linux-musleabihf      Pi Zero / Zero W / 1 (ARMv6)
ARM64_TARGET := aarch64-unknown-linux-musl
ARMV7_TARGET := armv7-unknown-linux-musleabihf
ARMV6_TARGET := arm-unknown-linux-musleabihf

.PHONY: all build release static arm64 armv7 armv6 arm-all test clean fmt clippy

# Default: debug build for the host
all: build

build:
	cargo build

# Optimized host build
release:
	cargo build --release

# Statically-linked musl binary (no runtime dependencies)
static:
	rustup target add $(MUSL_TARGET)
	cargo build --release --target $(MUSL_TARGET)
	@mkdir -p $(DIST)
	cp target/$(MUSL_TARGET)/release/$(BINARY) $(DIST)/$(BINARY)-linux-amd64
	@ls -lh $(DIST)/

# Cross-compiled static ARM builds (requires `cargo install cross` + Docker)
arm64:
	cross build --release --target $(ARM64_TARGET)
	@mkdir -p $(DIST)
	cp target/$(ARM64_TARGET)/release/$(BINARY) $(DIST)/$(BINARY)-linux-arm64
	@ls -lh $(DIST)/

armv7:
	cross build --release --target $(ARMV7_TARGET)
	@mkdir -p $(DIST)
	cp target/$(ARMV7_TARGET)/release/$(BINARY) $(DIST)/$(BINARY)-linux-armv7
	@ls -lh $(DIST)/

armv6:
	cross build --release --target $(ARMV6_TARGET)
	@mkdir -p $(DIST)
	cp target/$(ARMV6_TARGET)/release/$(BINARY) $(DIST)/$(BINARY)-linux-armv6
	@ls -lh $(DIST)/

arm-all: arm64 armv7 armv6

test:
	cargo test

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean
	rm -rf $(DIST)
