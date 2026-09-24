# Plonky2 zk-email circuits

Rust port of `zk-email-verify/packages/circuits`, using Plonky2 1.1.0 over
Goldilocks. SHA-256 and RSA arithmetic are constrained inside the proof;
host computations only supply witnesses. Examples and tests are independent of
the original Circom tree.

## Build and test

The pinned, locally available nightly is required by
[Plonky2](https://github.com/0xPolygonZero/plonky2#building).

```sh
cargo test -- --nocapture --test-threads=1
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo run --release --example verify_email
```

Tests include real proof generation and verification. RSA/email proofs are
expensive; sequential test execution limits peak memory.
If the default Cargo cache is read-only, set `CARGO_HOME` to a writable path.
Examples and Rust circuit tests print unpadded constraint gate rows and padded
trace rows. Plonky2 gates have different numbers of equations, so these are
circuit-size measures, not an R1CS-style count of individual constraints.

## Complete example from a real .eml file

With Node.js 18+ installed (no npm packages required), run:

```sh
cargo run --release --example verify_eml
```

This reads the self-contained `examples/fixtures/test.eml` fixture and:

1. Restores SMTP line endings, parses folded headers, and applies DKIM
   relaxed/relaxed canonicalization, selecting signed headers in `h=` order.
2. Checks the body hash and RSA signature using Node's built-in crypto and the
   pinned public record in `examples/fixtures/icloud-dkim.json`.
3. Pads the canonicalized header and complete body for SHA-256 and prepares the
   Plonky2 witnesses. The example constrains the body chaining state to SHA's
   initial state, disabling prefix skipping for this proof.
4. Calls `plonky2_zkemail::eml::prove` to build the circuit, generate a
   zero-knowledge proof, and verify it.

The default email is signed by `icloud.com`, selector `1a1hai`. The checked-in
public record includes its retrieval date and DNS/archive source URLs. It is
an explicit trust anchor for this historical example, not a live DNS lookup
or a claim about present-day key validity. The flow is offline after Cargo
dependencies are available. Proof generation can take several minutes.

To select another email and an independently trusted public-key record:

```sh
cargo run --release --example verify_eml -- /path/to/email.eml /path/to/trusted-key.json
```

The key JSON uses the same `domain`, `selector`, and `record` fields as the
included fixture. The adapter in `examples/eml/prepare.mjs` intentionally
supports one `rsa-sha256` signature, `relaxed/relaxed` canonicalization, a
2048-bit RSA/SPKI key with exponent 65537, and the circuit's `bh=` formatting.
It rejects `l=` partial-body signatures, duplicate tags, unsupported modes,
and domain/selector mismatches. It is a bounded example, not a general mail
server DKIM/DMARC verifier; it does not apply expiration or sender-alignment
policy. Canonicalization follows [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376).

Fast preparation and regression checks (without generating a large proof):

```sh
node --test examples/eml/prepare.test.mjs
cargo test --lib embedded_helper_prepares_fixture
```

These cover the existing Circom fixture's header digest, line endings,
folding, repeated signed headers, body/header tampering, and incorrect keys.
`verify_email` remains available as the smaller synthetic circuit example.

## Circuit mapping

| Circom functionality | Rust interface |
| --- | --- |
| `Sha256Bytes`, `Sha256BytesPartial` | `sha256::sha256_padded`, optional precomputed state |
| `Sha256General`, `Sha256Partial` | `sha256::sha256_bits_padded` |
| Fixed-length SHA-256 with generated padding | `sha256::sha256` |
| `BigLessThan`, `FpMul` | `bigint::less_than`, `ModMulTarget` |
| `CheckCarryToZero`, bigint witness functions | Bounded integer convolution/carry constraints and `BigUint` witness calculations |
| `RSAPad` | `rsa::rsa_pad`, constrained variable-size PKCS#1 v1.5 encoding |
| `FpPow65537Mod`, `RSAVerifier65537` | `rsa::RsaTarget` (16 squarings and one multiplication, bound to the padded digest) |
| `EmailVerifier`, all four optional features | `email::EmailTarget`, `EmailCircuit`, `EmailConfig` |
| `ItemAtIndex`, `VarShiftLeft`, `SelectSubArray`, `AssertZeroPadding` | Corresponding snake-case functions in `utils` |
| `Slice`, `CalculateTotal` | Rust slices, `CircuitBuilder::add_many` |
| `PackBytes`, `PackByteSubArray`, `PackBits`, `SplitBytesToWords`, `DigitBytesToInt`, `ByteMask` | Corresponding snake-case functions in `utils` |
| `AssertBit` | `CircuitBuilder::assert_bool` / `add_virtual_bool_target_safe` |
| `Base64Decode` | `utils::base64_decode` (includes character lookup constraints) |
| `CheckSubstringMatch`, `CountSubstringOccurrences`, `RevealSubstring` | Corresponding snake-case functions in `utils` |
| `SelectRegexReveal`, `PackRegexReveal` | Corresponding snake-case functions in `utils` |
| External `BodyHashRegex` | `regex::body_hash_regex`, with constrained DFA transitions |
| `PoseidonLarge`, `PoseidonModular`, `EmailNullifier` | Corresponding snake-case functions in `utils`, native Plonky2 Poseidon |
| `RemoveSoftLineBreaks`, `CleanEmailAddress` | Exact constrained byte compaction in `utils` |

## Representation and compatibility

* RSA values use little-endian **16-bit limbs**, up to 4096 bits. Never convert
  a Circom 121-bit limb directly into a Goldilocks element. Use
  `bigint::from_circom_limbs` to reconstruct a `BigUint`, then the target's
  `set` method. The maximum key byte length is fixed per circuit; use 128 for
  up to 1024-bit or 256 for up to 2048-bit RSA. Padding follows the actual
  modulus byte length, so a 2048-bit circuit also supports 1024-bit keys.
  The modulus must be odd and large enough for PKCS#1 padding; signatures
  and intermediate remainders are canonical and strictly smaller than it.
* SHA inputs and outputs are bytes in network order. The bit API uses
  big-endian bits. Variable-length inputs are already SHA-padded; their lengths
  are positive multiples of 64. The low-level `sha256_padded` API leaves padding
  syntax to its caller; `sha256::pad` prepares it. The email circuit additionally
  constrains canonical SHA-256 padding and zeroes every byte beyond the selected
  padded length.
* Partial SHA accepts a big-endian **compression chaining state**, not the
  finalized digest of a prefix. It processes the supplied suffix including the
  original message's final padding. By default the email circuit pins this state
  to `sha256::IV`, so it hashes the complete supplied body. Set
  `EmailConfig::allow_partial_body_hash` only when a trusted external statement
  binds the omitted prefix and chaining state. The partial mode does not prove
  knowledge of skipped prefix bytes or validate the suffix's full-message
  padding; it must not be treated as full-body DKIM verification.
* Native Poseidon outputs **four Goldilocks elements**, not a BN254 scalar.
  `poseidon` hashes `[input_length, ...input]` with Plonky2's native no-pad sponge.
  `poseidon_large` merges pairs of bounded limbs (at most 31 bits each), then
  calls `poseidon`. `poseidon_modular` hashes chunks of 16 and folds their
  four-element digests. The nullifier hashes the full signature digest again.
  Existing Circom commitments/nullifiers must be recomputed.
* Byte packing uses **7 bytes per field element**, rather than Circom's 31.
  Bit packing supports widths up to 63. Header SHA output is 32 public bytes,
  replacing two 128-bit field elements. Decimal conversion supports at most
  19 digits, so the result is an integer below the Goldilocks modulus.
* Array extraction has explicit bounds and rejects wrapping substrings.
  `var_shift_left` itself retains the original cyclic shift semantics.
  Substring matching retains Circom's zero-as-wildcard pattern semantics.
  Regex reveal selection constrains both prefix and suffix bytes to zero.
* The body-hash recognizer ports the DFA and reveal rules from the source's
  `@zk-email/zk-regex-circom` 2.3.2 dependency, including UTF-8 and restart rules.
  It implements `(\r\n|^)dkim-signature:([a-z]+=[^;]+; )+bh=[a-zA-Z0-9+/=]+;`
  and selects a 44-byte reveal at the supplied index inside the authenticated
  header. Ambiguous multiple reveals are rejected by bounded reveal selection.
  Base64 preserves the source's permissive `=`-as-zero decoding; it is not a
  canonical Base64 validator.
* Cleaning helpers use exact compaction, not the source's Poseidon-derived
  random linear comparison. This avoids weakening those checks in a 64-bit
  field. Email cleaning assumes a valid address, as does the source. Soft-break
  removal processes the full supplied buffer, including SHA padding, matching
  the source. Decoded bytes remain private unless explicitly registered.

## Public statement and use

`EmailCircuit::build` enables zero knowledge and registers public inputs in
this order: public-key Poseidon digest (4), header SHA-256 digest (32), optional
masked header (`max_header_bytes`), optional masked body (`max_body_bytes`).
The signature, header, body, and masks are private witnesses. The body's
precomputed state is fixed to SHA-256's IV unless partial mode is explicitly
enabled.
For custom statements, compose `EmailTarget::new` in your own builder and
register the outputs you need. Use `circuit_config()` to enable zero knowledge.

The verifier must check public inputs against its expected key commitment and
application policy; accepting any public key does not authenticate a sender.
DNS lookup, DKIM canonicalization, key trust, and extraction of raw `.eml`
messages remain outside this circuit, as in the original project. This crate
accepts the canonicalized, padded inputs normally supplied by those helpers.
See `examples/verify_eml.rs` for the raw-email flow above, or
`examples/verify_email.rs` for a smaller synthetic signed fixture. Neither
example stores private signing keys.

This is a new implementation, not an audited replacement. Its proofs and
public-input encoding are incompatible with the original Groth16 verifier.
