# mpz-core (vendored)

Copy of `crates/core` of [mpz](https://github.com/privacy-scaling-explorations/mpz)
at rev `ccc0057`, the revision the workspace depends on, with one upstream change
backported:

- [`3d90b6c`](https://github.com/privacy-scaling-explorations/mpz/commit/3d90b6c)
  "chore: update hybrid array version (#326)": `hybrid-array` 0.3 -> 0.4.

Why: `iroh` (used by `k5net`) depends on the stable RustCrypto stack
(`crypto-common` 0.2, `hybrid-array` 0.4). At `ccc0057`, `mpz-core` pins
`hybrid-array` 0.3, which only works with pre-releases of `aes` 0.9 / `cipher`
0.5 that cannot share a `Cargo.lock` with it. The source is unchanged; only the
manifest differs (standalone instead of inheriting from mpz's workspace, benches
dropped).

It replaces the git crate through `[patch]` in the root `Cargo.toml`. Remove it
once the workspace moves to an mpz revision that includes `3d90b6c`.

Licensed, like mpz, under either of Apache License 2.0 or MIT, at your option.
