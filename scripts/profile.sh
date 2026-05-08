#!/usr/bin/env bash
#
# Run <command> <args>, wait 5 seconds, then attach `perf record -g`
# for the rest of the process's lifetime.
#
# Usage:   ./profile.sh <command> [args...]
# Output:  ./perf.data   (override with PERF_DATA=path)
#          PERF_FREQ env var sets sampling frequency (default 999 Hz)
#
# Build the target binary with `RUSTFLAGS='-C force-frame-pointers=yes'`
# for usable stack traces.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 1
fi

if ! command -v perf >/dev/null 2>&1; then
    echo "error: 'perf' not found - install linux-perf / perf-tools" >&2
    exit 1
fi

PERF_DATA="${PERF_DATA:-./perf.data}"
PERF_FREQ="${PERF_FREQ:-999}"
ATTACH_DELAY="${ATTACH_DELAY:-5}"

printf '[profile] command:'
printf ' %q' "$@"
printf '\n'
printf '[profile] attach delay=%ss  freq=%sHz  output=%s\n' \
    "$ATTACH_DELAY" "$PERF_FREQ" "$PERF_DATA"

"$@" &
TARGET_PID=$!

PERF_PID=""
cleanup() {
    if [[ -n "$PERF_PID" ]] && kill -0 "$PERF_PID" 2>/dev/null; then
        kill -INT "$PERF_PID" 2>/dev/null || true
        wait "$PERF_PID" 2>/dev/null || true
    fi
    if kill -0 "$TARGET_PID" 2>/dev/null; then
        kill "$TARGET_PID" 2>/dev/null || true
        wait "$TARGET_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

sleep "$ATTACH_DELAY"

if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "[profile] error: target process exited before perf could attach" >&2
    exit 1
fi

echo "[profile] attaching perf to PID $TARGET_PID"
perf record -g -F "$PERF_FREQ" -p "$TARGET_PID" -o "$PERF_DATA" >/dev/null 2>&1 &
PERF_PID=$!

set +e
wait "$TARGET_PID"
RC=$?
set -e

kill -INT "$PERF_PID" 2>/dev/null || true
wait "$PERF_PID" 2>/dev/null || true
PERF_PID=""

trap - EXIT INT TERM

echo "[profile] done (exit=$RC), perf data: $PERF_DATA"
echo "[profile] inspect with: perf report -i $PERF_DATA"
exit "$RC"
