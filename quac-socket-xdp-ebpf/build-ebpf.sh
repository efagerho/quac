#!/usr/bin/env bash
#
# Build the AF_XDP eBPF program and copy the resulting object next to
# Cargo.toml so quac-socket-xdp's `include_bytes!` picks it up.
#
# Prereqs (one-time):
#   rustup toolchain install nightly
#   rustup component add rust-src rustc-dev --toolchain nightly
#   rustup target add bpfel-unknown-none --toolchain nightly
#   cargo install bpf-linker          # plus llvm-devel / libclang-dev
#
# Re-run this script whenever src/main.rs changes; the host build of
# quac-socket-xdp picks up the new bytes on its next compile.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

cargo +nightly build --release --features ebpf \
    --target bpfel-unknown-none \
    -Z build-std=core,compiler_builtins \
    -Z build-std-features=compiler-builtins-mem

OUT="target/bpfel-unknown-none/release/quac-socket-xdp-prog"
if [[ ! -f "$OUT" ]]; then
    echo "error: expected build output not found at $OUT" >&2
    exit 1
fi

# Verify it's actually a BPF ELF and not a fallback host-target binary.
if ! file "$OUT" | grep -q "eBPF"; then
    echo "error: $OUT is not a BPF ELF object:" >&2
    file "$OUT" >&2
    echo "  bpf-linker may have silently fallen back; check its dlopen warnings." >&2
    exit 1
fi

cp "$OUT" "$SCRIPT_DIR/quac-socket-xdp-prog"
echo "wrote $SCRIPT_DIR/quac-socket-xdp-prog ($(stat -c%s "$SCRIPT_DIR/quac-socket-xdp-prog") bytes)"
