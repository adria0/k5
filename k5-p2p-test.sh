#!/usr/bin/env bash
# Two k5 clients, Alice and Bob, to test peer-to-peer communication.
#
# Creates both identities in DIR (default: ./p2p-test, replaced), has them
# keysign each other, gives each its own 10 fake identities (`fakegraph`,
# with a different seed each), all on its web of trust, and the attestations
# of adria0's X, GitHub and website (notarized as in k5-test.sh, with
# k5cli's local notary). Then makes the first contact between Alice and Bob
# (a ticket, over n0's network) so each knows how to reach the other, checks
# that a message from Alice reaches Bob, and opens a k5gui for each. In
# either window: search the other, open its dossier, MESSAGES or SYNC;
# received messages appear in CHATS.
#
# With --no-gui, also checks that Alice can sync with Bob, and stops there
# instead of opening the windows: a self-checking run (it needs n0).
#
# Usage: ./k5-p2p-test.sh [--no-gui] [DIR]

set -euo pipefail

GUI=1
if [ "${1:-}" = "--no-gui" ]; then
    GUI=0
    shift
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIR="$(mkdir -p "${1:-p2p-test}" && cd "${1:-p2p-test}" && pwd)"
K5CLI="$ROOT/target/release/k5cli"
K5GUI="$ROOT/target/release/k5gui"

if [ "$GUI" = 1 ]; then
    echo "Building k5cli and k5gui ..."
    cargo build --release --manifest-path "$ROOT/Cargo.toml" -p k5cli -p k5gui
else
    echo "Building k5cli ..."
    cargo build --release --manifest-path "$ROOT/Cargo.toml" -p k5cli
fi

rm -rf "$DIR/alice" "$DIR/bob"
mkdir -p "$DIR/alice" "$DIR/bob"

# Profiles of adria0, as notarized by k5-test.sh.
ADRIA0_URLS=(
    https://x.com/adria0/status/2103557323306225669
    https://gist.githubusercontent.com/adria0/5113512aa7121ada3e5a75e7d7f3d791/raw/be13d239b4b4fd2068973099bba9b27e8bf8624a/gistfile1.txt
    https://ethbcn.dev/k5.txt
)
# Number of fake identities of each client, and their seeds: different, so
# each client knows different people.
IDENTITIES=10
ALICE_SEED=0xa11ce
BOB_SEED=0xb0b

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

echo "Generating $IDENTITIES identities for each ..."
cli alice fakegraph "$IDENTITIES" "$ALICE_SEED" >/dev/null
cli bob fakegraph "$IDENTITIES" "$BOB_SEED" >/dev/null

# Notarized once, by Alice; the records verify anywhere (both windows expect
# the local notary's key), so Bob gets a copy. A notarization that fails (no
# network, a changed page) is reported and skipped.
echo "Notarizing adria0's profiles (this takes a while) ..."
NOTARIZE_LOG="$DIR/alice/notarize.log"
for url in "${ADRIA0_URLS[@]}"; do
    out=""
    # `attest new` prints the stored record last, relative to its directory.
    if out="$(cli alice attest new "$url" 2>>"$NOTARIZE_LOG")" &&
        record="$(tail -n1 <<<"$out")" && [ -f "$DIR/alice/$record" ]; then
        cp "$DIR/alice/$record" "$DIR/bob/$record"
        echo "  $(basename "$record")"
    else
        echo "  FAILED $url (see $NOTARIZE_LOG)" >&2
    fi
    printf '%s\n' "$out" >>"$NOTARIZE_LOG"
done

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
    echo "No ticket from Bob's listener after 30s (is n0 reachable?):" >&2
    cat "$LISTEN_LOG" >&2
    exit 1
fi

RUST_LOG=warn cli alice p2p connect "$TICKET" 2>/dev/null

# While Bob still listens: Alice finds him by his k5 (through n0) and
# delivers a message to his inbox.
echo "Checking a message from Alice to Bob ..."
RUST_LOG=warn cli alice p2p send "k5:$BOB" "hello bob, from the p2p test" 2>/dev/null
# Captured first: with pipefail, `grep -q` stopping early fails the pipe.
INBOX="$(cli bob p2p inbox)"
if ! grep -q "hello bob, from the p2p test" <<<"$INBOX"; then
    echo "The message did not reach Bob's inbox:" >&2
    cat "$LISTEN_LOG" >&2
    exit 1
fi
echo "  delivered"

# Syncing gives Alice Bob's identities too, so only without the windows,
# which show each client its own.
if [ "$GUI" = 0 ]; then
    echo "Checking that Alice syncs with Bob ..."
    RUST_LOG=warn cli alice p2p sync "k5:$BOB" 2>/dev/null | tail -n 3
    LISTING="$(cli alice attest list 2>/dev/null)"
    if ! grep -q "signer: k5:$BOB" <<<"$LISTING"; then
        echo "Alice did not merge Bob's keysigns" >&2
        exit 1
    fi
    echo "  synced"
fi

kill "$LISTENER" 2>/dev/null || true
wait "$LISTENER" 2>/dev/null || true
trap - EXIT

if [ "$GUI" = 0 ]; then
    echo
    echo "All checks passed ($DIR)."
    exit 0
fi

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
echo "Search \"Alice\", \"Bob\" or \"adria0\" in either window. Ctrl-C closes both."
wait
