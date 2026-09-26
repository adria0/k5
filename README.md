# k5

**A web of trust for online identities, with post-quantum keys.**

Your identity in k5 is your *k5*: the fingerprint of an OpenPGP v6 key with a
post-quantum composite `MlDsa65Ed25519` signing key and an `MlKem768X25519`
encryption subkey. Around it you collect **attestations** that link the k5 to
the rest of your online life, share them with people you trust, and talk to
them privately:

- **Profiles, proven with TLSNotary**: notarize a tweet, a GitHub gist or a
  `k5.txt` on your website that contains your k5. The attestation proves the
  server really returned it, without trusting you.
- **Keysigns**: as in a PGP key signing party, attest that you know the owner
  of a k5. Keysigns form the web of trust: the k5s reachable from yours.
- **Messages**: sign, or sign and encrypt (signcrypt) to a k5, with its
  published post-quantum key.
- **Peer to peer**: deliver messages and merge each other's attestations
  directly, over [iroh](https://www.iroh.computer), with anyone on your web of
  trust.

> [!WARNING]
> k5 is experimental. It relies on rpgp's `draft-pqc` implementation of
> draft-ietf-openpgp-pqc, which is not stable yet: formats may change. Do not
> use it for anything that matters.

## Quick start

```sh
cargo build --release -p k5cli -p k5gui

k5cli init                    # create k5.toml with your keys
k5cli me                      # print your k5
k5cli attest new https://x.com/<you>/status/<id>   # a tweet containing your k5
k5cli attest list             # verify and list the attestations
k5gui                         # the desktop interface
```

`k5cli.sh` and `k5gui.sh` run them through `cargo run --release`. `k5-test.sh`
is an end-to-end run of most commands, in the repository root (it deletes
`db/` first, and stops at the first failure). `k5-p2p-test.sh` sets up two
clients, Alice and Bob, pairs them over n0, checks a message gets through and
opens a window for each; `k5-p2p-test.sh --no-gui` also checks sync and stops
there, as a self-checking run.

## Attestations

Everything lives next to where you run the tools:

- `k5.toml`: your keys (and, once online, your iroh key). Keep it private.
- `db/attestations/`: the attestations, one markdown record per file, named
  after the k5 they are about. They are verified every time they are read.
- `db/inbox/`: messages received peer to peer, still encrypted.

Record types:

| Type               | What it proves                                                     |
|--------------------|--------------------------------------------------------------------|
| `tlsn`             | a TLSNotary-notarized session: a profile on X, GitHub or a website |
| `keysignparty`     | a k5 attests it knows the owner of another k5                      |
| `self_attestation` | a k5 publishes its public keys (created automatically)             |
| `iroh`             | the iroh endpoint a k5 can be reached at (created when online)     |
| `name`             | the name a k5 claims for itself (signed by that k5)                |
| `zkemail`          | an email address: a zero-knowledge proof of a DKIM-signed email    |

Supported profiles (`k5cli attest new <url>`):

- **X**: `https://x.com/<user>/status/<id>`, a tweet containing your k5.
- **GitHub**: `https://gist.githubusercontent.com/<user>/<id>/raw/...`, a
  gist containing your k5.
- **Website**: `https://<domain>/k5.txt` containing `k5:<your k5>`.

And your email address, with `k5cli attest email <message.eml>` (or MY EMAIL
in the desktop interface): send an email from that address to yourself with
`k5:<your k5>` in the subject, and save it as a `.eml` file. Its DKIM key is
fetched from DNS (`<selector>._domainkey.<domain>`) and a Plonky2 proof shows
the email's signed header was signed by that key, which takes a few minutes.
The attestation publishes the signed headers (From, To, Subject, Date...) and
the DKIM key, not the body. It is valid if the proof verifies, there is one
`From` of the DKIM domain (or a subdomain), and the subject has the k5. As
with any zk-email, it trusts the DKIM key as published when it was made.

Without `--notary-host`, `attest new` runs a notary in-process, signing with
the key embedded in k5cli (`crates/k5cli/local-notary.pem`), which is also the
default key attestations are verified against (`--notary-key`). Since that key
is public, the default setup is for development: anyone can sign as that
notary.

### Sharing

```sh
k5cli attest keysign k5:<their k5> "Their Name"
k5cli attest export            # export.md: your attestations, signed
k5cli attest merge export.md   # merge someone's export
```

A merge only takes what is on your web of trust: keysigns whose signer you can
reach through keysigns, and other attestations about k5s you can reach.

## Messages

```sh
k5cli msg sign "hello"
k5cli msg signcrypt k5:<their k5> "hello, privately"
k5cli msg verify msg.md
```

Signcrypting needs the recipient's self attestation in your database.

## Peer to peer

k5s talk directly over iroh, addressed by public key. A k5 cannot be dialed by
its id (a fingerprint), so each k5 has its own iroh key, in the `[iroh]`
section of `k5.toml`, and publishes its endpoint in an `iroh` attestation
signed with the k5 key. Those records travel with the others through export,
merge and sync, so the web of trust is how k5s find each other; n0's address
lookup and relays find the way to the endpoint. On every connection both sides
prove their k5 and check the other is on their web of trust.

First contact is a pairing, by ticket. A ticket opens a 10 minute pairing
window, during which k5s not on your web of trust yet may connect with it:
both sides store each other's records and print the same **check phrase**
(four words). Compare them (aloud, or on a call): if they match, you paired
with who you think, so keysign each other; until then, neither serves the
other.

```sh
# Alice
k5cli p2p listen               # prints a ticket, serves until Ctrl-C
# Bob
k5cli p2p connect k5ticket:... # both learn how to reach each other, and
                               # print the check phrase
k5cli attest keysign k5:<alice> "Alice"   # if the phrases match (both sides)
```

From then on, by k5:

```sh
k5cli p2p send k5:<alice> "hi"  # sign, encrypt and deliver
k5cli p2p sync k5:<alice>       # merge Alice's attestations
k5cli p2p inbox                 # read the messages received
```

Both peers must be online: messages are not stored and forwarded. n0's
servers see endpoint ids and IP addresses, never k5s or message content.

## Desktop interface

`k5gui` searches the attestations, shows the dossier of an identity (profiles,
trust path), sends it messages, syncs with it, and shows the inbox. It goes
online at start. The menu of the main screen (the three lines) has:

- `ME`: your attestations.
- `VERIFY`: paste a signed message, a message for you or an attestation
  record, and see who signed it and whether they are on your web of trust.
- `CREATE INVITE` (a ticket, also shown as a QR code) and `ACCEPT INVITE`
  (paste or scan one): the first contact, a pairing. Both windows show the check phrase; if they match, keysign the
  other from the dialog.
- `AUTO SYNC`: every minute, the trusted k5s that can be reached peer to peer
  are checked for presence (`P2P · ONLINE`), and every 10 minutes their
  attestations are merged. On by default.
- `ATTEST`: attest your X, GitHub or website: publish your k5 there, paste the
  URL (or type the domain) and a remote TLSNotary notary attests it. Email
  attestations are not available yet.

```sh
k5gui [--config k5.toml] [--db db] [--offline] \
      [--notary-host <host> [--notary-port 7047] [--notary-tls]] [--notary-key <hex>]
```

On the first run, if the config file does not exist, `k5gui` creates it with
new keys, as `k5cli init` does.

Attesting needs `--notary-host`, and the notary must sign with `--notary-key`
(the default is the key of `k5cli`'s local notary). Presentations are written
to `<db>/presentations/`.

To try two clients on one machine: `k5gui --config a.toml --db a/` and
`k5gui --config b.toml --db b/`.

## Android

The same window runs on Android phones (`crates/k5android`, arm64). It is
built with [cargo-apk](https://github.com/rust-mobile/cargo-apk) inside a
Docker image with the Android SDK and NDK, so nothing Android needs to be
installed:

```sh
./k5-android.sh            # target/android/release/apk/k5.apk
./k5-android.sh --install  # and install it with adb
```

It needs Docker (Docker Desktop or OrbStack; on Apple Silicon, with Rosetta
for x86_64 images, as the NDK only exists for x86_64 Linux). The first build
takes a long while; later ones are incremental. The APK is signed with a debug
key kept in a Docker volume: fine for your own devices, not for publishing.

The keys and the database live in the app's private storage, created on the
first launch. Until the app has a settings screen, the notary for `ATTEST` is
set in the `[notary]` section of its `k5.toml`:

```sh
adb shell run-as dev.k5.app cat files/k5.toml   # the app's config
adb logcat -s k5                               # its logs
```

```toml
[notary]
host = "notary.example.com"
port = 7047      # optional
tls = true       # optional
```

The desktop `k5gui` reads the same section when `--notary-host` is not given.

## Tools

```sh
k5cli fakegraph 50             # a deterministic fake social graph, for testing
k5cli makedot                  # graph.dot: the web of trust, for Graphviz
```

## Crates

- [`k5lib`](./crates/k5lib/): the k5 library: keys, attestations, messages,
  the database (`Db` trait, `FsDb`).
- [`k5net`](./crates/k5net/): peer to peer over iroh.
- [`k5cli`](./crates/k5cli/): the command line, with the in-process notary.
- [`k5gui`](./crates/k5gui/): the desktop interface (Slint).
- [`k5android`](./crates/k5android/): the same interface as an Android app.

The other crates are the TLSNotary implementation k5 builds on, and
`vendor/mpz-core` a patched copy of one of its dependencies (see its README).

## Building

k5 builds with a pinned nightly Rust (`rust-toolchain.toml`): Plonky2, the
proof system of email attestations, needs it. rustup installs it on the first
build. Proving emails is much faster in release builds.

If the build fails with:

```
Could not find directory of OpenSSL installation, and this `-sys` crate cannot
  proceed without this knowledge.
```

install the OpenSSL development packages (`libssl-dev` on Ubuntu,
`openssl-devel` on Fedora).

## License

Licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
