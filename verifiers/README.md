# Groth16 verifier (BN254) in Fe

This ingot contains a Groth16 verifier for BN254.

## Layout
- Verifier module (demo VK): `verifiers/src/groth16_bn254.fe`
- Public exports + contract wrapper: `verifiers/src/lib.fe`

## Adapting to your circuit
`verifiers/src/groth16_bn254.fe` is circuit-specific: replace the `verifying_key_*` constants (including `verifying_key_ic`) with the values generated for your circuit.

## Disclaimer:

**This implementation has not been reviewed or audited. Use at your own risk.** 
We do not give any warranties and will not be liable for any losses incurred through any use of this code base.
