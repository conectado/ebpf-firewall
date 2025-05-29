CC=aarch64-linux-musl-gcc cargo build --package firewall --release   --target=aarch64-unknown-linux-musl   --config=target.aarch64-unknown-linux-musl.linker="aarch64-linux-musl-gcc"
