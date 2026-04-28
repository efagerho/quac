#!/usr/bin/env bash
# shellcheck shell=bash
# Shared helpers for profile_{os,iouring}_socket_bench.sh (sourced, not executed).

socket_bench_require_linux() {
  if [[ "$(uname -s)" != Linux ]]; then
    echo "error: these scripts use perf(1) on Linux only." >&2
    exit 1
  fi
  if ! command -v perf >/dev/null 2>&1; then
    echo "error: perf(1) not found (install linux-tools or equivalent)." >&2
    exit 1
  fi
}

# Build benchmarks release binary with frame pointers so perf can unwind stacks.
socket_bench_build() {
  local root=$1
  (cd "$root" && RUSTFLAGS="-C force-frame-pointers=yes" \
    cargo build --release -p benchmarks \
      --bin os_socket_bench \
      --bin iouring_socket_bench \
      --bin blaster)
}

# Wait until a UDP port is bound (up to 120s).
socket_bench_wait_udp() {
  local port=$1
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if command -v ss >/dev/null 2>&1; then
      if ss -ulnH 2>/dev/null | grep -qE ":${port}([^0-9]|$)"; then
        return 0
      fi
    fi
    sleep 0.05
  done
  echo "error: timed out waiting for UDP port $port" >&2
  return 1
}

# Convert perf.data → SVG flamegraph; falls back to a perf-report text summary.
socket_bench_perf_to_svg() {
  local perf_data=$1
  local svg=$2
  if [[ ! -s "$perf_data" ]]; then
    echo "error: missing or empty perf data: $perf_data" >&2
    return 1
  fi
  if command -v inferno-collapse-perf >/dev/null 2>&1 && command -v inferno-flamegraph >/dev/null 2>&1; then
    perf script -i "$perf_data" | inferno-collapse-perf | inferno-flamegraph >"$svg"
    echo "Flamegraph written to: $svg" >&2
    return 0
  fi
  if command -v stackcollapse-perf.pl >/dev/null 2>&1 && command -v flamegraph.pl >/dev/null 2>&1; then
    perf script -i "$perf_data" | stackcollapse-perf.pl | flamegraph.pl >"$svg"
    echo "Flamegraph written to: $svg" >&2
    return 0
  fi
  echo "warning: inferno or FlameGraph not found; raw perf data kept at: $perf_data" >&2
  echo "  Install: cargo install inferno" >&2
  return 1
}

# Print a flat perf report (top functions by overhead) to stdout.
socket_bench_perf_report() {
  local perf_data=$1
  perf report -n --stdio -i "$perf_data" 2>/dev/null \
    | grep -v "^#\|^$\|Samples\|overhead" \
    | head -60 \
    || perf report -n --stdio -i "$perf_data" 2>/dev/null | head -80
}
