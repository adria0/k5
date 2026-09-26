#!/usr/bin/env bash
# End-to-end run of most k5cli commands, in the repository root, with its
# k5.toml (created if missing) and a fresh db/: notarizes adria0's X, GitHub
# and website with k5cli's local notary, keysigns, generates a fake graph,
# lists, searches, audits, exports and merges, and signs, signcrypts and
# verifies messages. Stops at the first failure.
#
# Replaces db/, and writes export.md, graph.dot, msg.md and
# presentation.tlsn here.
#
# Usage: ./k5-test.sh

set -euo pipefail

cd "$(dirname "$0")"

echo "Building k5cli ..."
cargo build --release -p k5cli
K5="$PWD/target/release/k5cli"

step() {
    echo
    echo "== k5cli $*"
    "$K5" "$@"
}

rm -rf db
[ -f k5.toml ] || step init

step attest new https://x.com/adria0/status/2103557323306225669
step attest new https://gist.githubusercontent.com/adria0/5113512aa7121ada3e5a75e7d7f3d791/raw/be13d239b4b4fd2068973099bba9b27e8bf8624a/gistfile1.txt
step attest new https://ethbcn.dev/k5.txt
# `attest new` succeeds without storing anything when the page shows no
# profile: check the three were attested (search matches the user: the
# handle, or the domain).
FOUND="$("$K5" attest search 'adria0|ethbcn\.dev')"
for profile in X:adria0 github:adria0 site:ethbcn.dev; do
    if ! grep -q "$profile" <<<"$FOUND"; then
        echo "Missing attestation $profile:" >&2
        echo "$FOUND" >&2
        exit 1
    fi
done

step attest keysign k5:21e0a274bcf03711864c5eb1164a3a3735db671b058373ba6cf75acd4b214cbd "BobTheBuilder"
step attest search adria0
step fakegraph 5
step makedot
step attest list
step attest audit
step attest export
step attest merge
step msg sign "hello world"
step msg verify msg.md
step msg signcrypt "$("$K5" me)" "hello world cyphered"
step msg verify msg.md

echo
echo "All steps passed."
