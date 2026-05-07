# quac-socket-xdp-ebpf

eBPF program for `quac-socket-xdp`'s AF_XDP `XDP_REDIRECT` filter.

## Layout

- `src/lib.rs` — host-side: exposes the pre-built BPF object via
  `QUAC_SOCKET_XDP_EBPF_PROGRAM: &Aligned<[u8]>` for the userspace loader to
  consume.
- `src/main.rs` — kernel-side: the actual XDP program (added in Phase 5 of
  the AF_XDP rollout). `#[no_std]`, `#[no_main]`, only built when the `ebpf`
  feature is enabled.
- `quac-socket-xdp-prog` — committed pre-built BPF object. Currently a
  placeholder; Phase 5 ships the real one.

## Why outside the workspace

This crate's `[bin]` target requires the `bpfel-unknown-none` target and a
nightly toolchain. Making it a workspace member would force every
`cargo build --workspace` invocation to satisfy that toolchain — which most
contributors don't have installed. Instead we commit the pre-built object and
rebuild it manually when the source changes.

## Rebuilding the BPF object

One-time prerequisites:

```sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
rustup target add bpfel-unknown-none --toolchain nightly
```

Then from this directory:

```sh
cargo +nightly build --release --features ebpf \
    --target bpfel-unknown-none -Z build-std=core,compiler_builtins \
    -Z build-std-features=compiler-builtins-mem
cp target/bpfel-unknown-none/release/quac-socket-xdp-prog ./quac-socket-xdp-prog
```

Verify with:

```sh
file quac-socket-xdp-prog       # should print: ELF 64-bit LSB relocatable, eBPF, …
llvm-objdump -S quac-socket-xdp-prog | head -40
```

The committed file is what `quac-socket-xdp` `include_bytes!`s at compile time.
