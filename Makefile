BINARY      := vapx-scan
MUSL_TARGET := x86_64-unknown-linux-musl
DIST        := dist

.PHONY: all build release static test clean fmt clippy

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

test:
	cargo test

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean
	rm -rf $(DIST)
