# Fe v2 update (2026-01-26)

This document describes what changed in this repo during the “Fe v2” update, what was removed, and how to migrate any downstream usage.

## Summary

This repo started as older Fe v1-era code that:

- Implemented BN254 helpers using `std::precompiles` and `std::buf::MemoryBuffer`.
- Shipped a Groth16 verifier that built the pairing input via `MemoryBuffer` and called the pairing precompile.
- Included extra BN254 arithmetic (Fp/Fp2 ops, G2 arithmetic, hash-to-curve-ish helpers, and signing helpers).

The Fe v2 update refactors the repo to:

- Use the Fe v2 **workspace + ingot** structure.
- Use `std::evm::{alloc, ops}` and direct precompile `staticcall` wrappers for BN254 operations.
- Keep the Groth16 verifier, but express it in Fe v2 syntax and wire it to the BN254 wrappers.
- Remove artifacts that are not required to compile, test, or use the verifier library.

## Repository layout changes

### Before

- Two standalone “projects” with v1-style `fe.toml` manifests:
  - `crypto/` (BN254 + helpers)
  - `verifiers/` (Groth16 verifier + a `.fe.template`)

The v1 manifests were not compatible with the current Fe CLI (`fe 0.26.0`), and `fe check` failed with version parsing errors.

### After

- A single workspace root at `fe.toml` with two ingots:
  - `crypto/`
  - `verifiers/`

Files to look at:
- Workspace root: `fe.toml`
- Ingot manifests: `crypto/fe.toml`, `verifiers/fe.toml`
- Ingot entrypoints: `crypto/src/lib.fe`, `verifiers/src/lib.fe`

## BN254 implementation changes (`crypto` ingot)

### What was removed

The previous `crypto/src/curve/bn254.fe` contained far more than what the Groth16 verifier needs:

- Fp/Fp2 arithmetic helpers implemented via `modexp` and custom formulas.
- G2 curve arithmetic implemented in Fe.
- Hash/expand-message helpers and signing helpers (not appropriate for on-chain usage in most cases).

Those pieces were removed to keep the repo focused on on-chain verification via Ethereum precompiles.

### What replaced it

`crypto/src/bn254.fe` now provides **thin wrappers** around Ethereum’s BN254 precompiles:

- `0x06` ECADD
- `0x07` ECMUL
- `0x08` ECPAIRING

This is the same overall approach used in the `fe-verifiers` v2 codebase:

- Allocate input/output buffers with `std::evm::alloc`.
- Populate memory using `std::evm::ops::mstore`.
- Call precompiles with `std::evm::ops::staticcall`.
- Revert on failure via `std::evm::ops::revert(0, 0)`.

### G2 encoding detail (important)

The BN254 pairing precompile expects Fp2 coefficients in **reversed order** compared to the usual `(c0, c1)` math representation.

This repo stores `G2Point` as:

```
G2Point { x_c0, x_c1, y_c0, y_c1 }
```

…but when encoding for the pairing precompile, it writes:

```
x_c1, x_c0, y_c1, y_c0
```

That is handled internally by `store_pair` inside `crypto/src/bn254.fe`.

### Public API changes

Old code used:

- `std::precompiles::ec_add/ec_mul/ec_pairing`
- `std::buf::MemoryBuffer` for input packing
- Custom types like `Array<u256, 2>`

New code exposes:

- `G1Point` and `G2Point` structs (Fe v2 struct syntax)
- `negate`, `ec_add`, `ec_mul`
- `pairing_prod2/3/4` helpers that build the pairing input and perform the precompile call

`crypto/src/lib.fe` re-exports the BN254 module so consumers can `use crypto::bn254`.

## Groth16 verifier changes (`verifiers` ingot)

### What changed structurally

The Groth16 verifier implementation was moved into a dedicated module:

- `verifiers/src/groth16_bn254.fe`

`verifiers/src/lib.fe` re-exports it (so consumers can import `verifiers::groth16_bn254::*`) and contains a simple test.

### How the verifier works now

The verifier now:

- Validates the public input is `< SNARK_SCALAR_FIELD` and reverts otherwise.
- Computes `vk_x = IC[0] + IC[1] * public_input` using BN254 `ec_add`/`ec_mul`.
- Performs the Groth16 pairing product check using `bn254::pairing_prod4`.

### Compatibility function

`verifiers/src/groth16_bn254.fe` keeps a `verifyProof(a, b, c, input)` wrapper that matches the common SnarkJS call shape:

- `a` is `[u256; 2]` (G1)
- `b` is `[[u256; 2]; 2]` and is interpreted as `[[x_c1, x_c0], [y_c1, y_c0]]` (pairing precompile order)
- `c` is `[u256; 2]` (G1)
- `input` is `[u256; 1]` (this demo verifier has exactly one public input)

Internally it converts into the `Proof` struct and calls `verify`.

If you don’t need the SnarkJS-style wrapper, you can call `verify(Proof, public_input)` directly.

## Removals for minimalism

The following files were removed because they are not required to compile, test, or use the verifier library:

- `verifiers/src/main.fe` (example contract wrapper)
- `verifiers/src/groth16.fe.template` (EJS template convenience file)

If you want template-driven SnarkJS generation again, it can be reintroduced — but the v2 approach in `fe-verifiers` is typically “generate code, then paste constants”, rather than “swap the SnarkJS template”.

## How to validate the repo

From the workspace root:

- `fe check .`
- `fe test ./crypto`
- `fe test ./verifiers`

## Migration notes (v1 → v2)

If you had code importing the old v1 modules, the main changes are:

- Import paths changed:
  - From `crypto::curve::bn254::...` to `crypto::bn254::...`
- Precompile usage changed:
  - From `std::precompiles::*` + `MemoryBuffer` packing to `std::evm::{alloc, ops}` wrappers.
- Static arrays use Fe v2 syntax:
  - From `Array<u256, N>` to `[u256; N]`

## What’s intentionally not included (yet)

This repo currently focuses on Groth16 verification on BN254 using Ethereum precompiles.

The “extra” cryptographic utilities from the v1 code (Fp/Fp2 arithmetic, G2 math, hash-to-curve-ish helpers, signing helpers) were removed to keep the codebase minimal and aligned with on-chain best practices.

If you want to bring more back in Fe v2 style, the adjacent `fe-verifiers` workspace includes examples for:

- KZG point evaluation precompile wrapper (EIP-4844)
- BLS12-381 precompile wrappers (EIP-2537)

