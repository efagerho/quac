#!/usr/bin/env bash
# shellcheck shell=bash
# Shared helpers for profile_quic_pong_*.sh (sourced, not executed).

quic_pong_profile_require_linux() {
  if [[ "$(uname -s)" != Linux ]]; then
    echo "error: these scripts use perf(1) on Linux only." >&2
    exit 1
  fi
  if ! command -v perf >/dev/null 2>&1; then
    echo "error: perf(1) not found (install linux-tools or equivalent)." >&2
    exit 1
  fi
}

quic_pong_profile_build() {
  local root=$1
  # Force frame pointers so perf can unwind full Rust call stacks.
  (cd "$root" && RUSTFLAGS="-C force-frame-pointers=yes" cargo build --release -p benchmarks --bin quic_pong_tile --bin quic_bench)
}

# Best-effort: detect that something is bound on UDP /port/ (quic_pong uses UDP).
quic_pong_profile_wait_udp() {
  local port=$1
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if command -v ss >/dev/null 2>&1; then
      if ss -ulnH 2>/dev/null | grep -qE ":${port}([^0-9]|\$)"; then
        return 0
      fi
    fi
    if command -v lsof >/dev/null 2>&1; then
      if lsof -nP -iUDP:"$port" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 0.05
  done
  echo "error: timed out waiting for UDP port $port (is quic_pong running?)" >&2
  return 1
}

# Return VmRSS of a process in kB from /proc/<pid>/status.
quic_pong_get_rss() {
  local pid=$1
  if [[ -r "/proc/$pid/status" ]]; then
    awk '/^VmRSS:/{print $2; exit}' "/proc/$pid/status"
  else
    echo "0"
  fi
}

# Run N warmup rounds of a bench command against the pong server, sampling RSS
# after each round to detect memory leaks.
#
# Usage: quic_pong_warmup_rounds PONG_PID ROUNDS DRAIN_SECS BENCH_CMD [BENCH_ARGS...]
#   PONG_PID   — PID of the running pong server
#   ROUNDS     — number of warmup iterations (e.g. 10)
#   DRAIN_SECS — seconds to sleep after each round so connections can drain
#   BENCH_CMD… — the bench binary + arguments to run synchronously each round
#
# Prints per-round RSS and warns if RSS grew >15% from round 1 to round N.
quic_pong_warmup_rounds() {
  local pong_pid=$1
  local rounds=$2
  local drain_secs=$3
  shift 3

  local rss_baseline rss_first rss_last i rss growth
  rss_baseline=$(quic_pong_get_rss "$pong_pid")
  rss_first=0
  rss_last=0

  echo "  RSS baseline (idle): ${rss_baseline} kB" >&2

  for i in $(seq 1 "$rounds"); do
    echo "  warmup round $i/$rounds…" >&2
    "$@"
    sleep "$drain_secs"
    rss=$(quic_pong_get_rss "$pong_pid")
    echo "    RSS after round $i: ${rss} kB" >&2
    [[ $i -eq 1 ]] && rss_first=$rss
    rss_last=$rss
  done

  if [[ $rss_first -gt 0 ]]; then
    growth=$(( (rss_last - rss_first) * 100 / rss_first ))
    if [[ $growth -gt 15 ]]; then
      echo "" >&2
      echo "WARNING: possible memory leak — RSS grew ${growth}% across $rounds rounds" \
           "(round 1: ${rss_first} kB → round ${rounds}: ${rss_last} kB)" >&2
      echo "" >&2
    else
      echo "  RSS stable: round 1=${rss_first} kB → round ${rounds}=${rss_last} kB (Δ${growth}%)" >&2
    fi
  fi
}

# perf.script -> SVG (needs FlameGraph or inferno CLI on PATH).
quic_pong_profile_perf_to_svg() {
  local perf_data=$1
  local svg=$2
  if [[ ! -s "$perf_data" ]]; then
    echo "error: missing or empty perf data: $perf_data" >&2
    return 1
  fi
  if command -v inferno-collapse-perf >/dev/null 2>&1 && command -v inferno-flamegraph >/dev/null 2>&1; then
    perf script -i "$perf_data" | inferno-collapse-perf | inferno-flamegraph >"$svg"
    return 0
  fi
  if command -v stackcollapse-perf.pl >/dev/null 2>&1 && command -v flamegraph.pl >/dev/null 2>&1; then
    perf script -i "$perf_data" | stackcollapse-perf.pl | flamegraph.pl >"$svg"
    return 0
  fi
  echo "warning: could not find inferno-collapse-perf+inferno-flamegraph or stackcollapse-perf.pl+flamegraph.pl." >&2
  echo "  Raw perf data kept at: $perf_data" >&2
  echo "  Install inferno (cargo install inferno) or clone https://github.com/brendangregg/FlameGraph" >&2
  return 1
}
