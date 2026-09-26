#!/usr/bin/env bash
# Two k5 clients, Alice and Bob, to test peer-to-peer communication.
#
# Creates both identities in DIR (default: ./p2p-test, replaced), has them
# keysign each other, makes the first contact between them (a ticket, over
# n0's network) so each knows how to reach the other, then opens a k5gui for
# each. In either window: search the other, open its dossier, SEND MESSAGE
# (with CIPHER IT) or SYNC; received messages appear in the INBOX.
#
# Usage: ./k5-p2p-test.sh [DIR]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIR="$(mkdir -p "${1:-p2p-test}" && cd "${1:-p2p-test}" && pwd)"
K5CLI="$ROOT/target/release/k5cli"
K5GUI="$ROOT/target/release/k5gui"

echo "Building k5cli and k5gui ..."
cargo build --release --manifest-path "$ROOT/Cargo.toml" -p k5cli -p k5gui

rm -rf "$DIR/alice" "$DIR/bob"
mkdir -p "$DIR/alice" "$DIR/bob"

# k5cli keeps k5.toml and db/ in the directory it runs in.
cli() {
    local who="$1"
    shift
    (cd "$DIR/$who" && "$K5CLI" "$@")
}

echo "Creating the identities ..."
cli alice init >/dev/null 2>&1
cli bob init >/dev/null 2>&1
ALICE="$(cli alice me)"
BOB="$(cli bob me)"
echo "  alice  k5:$ALICE"
echo "  bob    k5:$BOB"

echo "Keysigning each other ..."
cli alice attest keysign "k5:$BOB" "Bob" >/dev/null
cli bob attest keysign "k5:$ALICE" "Alice" >/dev/null

# First contact: Bob listens, Alice connects with his ticket. Both store the
# other's self attestation (encryption key) and iroh attestation (endpoint),
# and get their iroh key in k5.toml, so the windows can reach each other by
# k5 right away.
echo "First contact over n0 ..."
LISTEN_LOG="$DIR/bob/listen.log"
(cd "$DIR/bob" && RUST_LOG=warn exec "$K5CLI" p2p listen >"$LISTEN_LOG" 2>&1) &
LISTENER=$!
trap 'kill "$LISTENER" 2>/dev/null || true' EXIT

TICKET=""
for _ in $(seq 60); do
    TICKET="$(grep -m1 '^k5ticket:' "$LISTEN_LOG" || true)"
    [ -n "$TICKET" ] && break
    if ! kill -0 "$LISTENER" 2>/dev/null; then
        echo "Bob's listener stopped:" >&2
        cat "$LISTEN_LOG" >&2
        exit 1
    fi
    sleep 0.5
done
if [ -z "$TICKET" ]; then
    echo "No ticket from Bob's listener after 30s:" >&2
    cat "$LISTEN_LOG" >&2
    exit 1
fi

RUST_LOG=warn cli alice p2p connect "$TICKET" 2>/dev/null
kill "$LISTENER" 2>/dev/null || true
wait "$LISTENER" 2>/dev/null || true
trap - EXIT

# Both windows at once; closing the script (Ctrl-C) closes them.
echo "Starting both k5gui ..."
"$K5GUI" --config "$DIR/alice/k5.toml" --db "$DIR/alice/db" >"$DIR/alice/gui.log" 2>&1 &
ALICE_GUI=$!
"$K5GUI" --config "$DIR/bob/k5.toml" --db "$DIR/bob/db" >"$DIR/bob/gui.log" 2>&1 &
BOB_GUI=$!
trap 'kill "$ALICE_GUI" "$BOB_GUI" 2>/dev/null || true' INT TERM EXIT

echo
echo "Alice: k5:$ALICE   (log: $DIR/alice/gui.log)"
echo "Bob:   k5:$BOB   (log: $DIR/bob/gui.log)"
echo "Search \"Alice\" or \"Bob\" in the other window. Ctrl-C closes both."
wait
