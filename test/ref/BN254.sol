// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BN254 (alt_bn128) precompile wrappers for Ethereum
/// @notice Minimal, production-style wrappers around EIP-196 (ECADD/ECMUL) and EIP-197 (PAIRING).
/// @dev
///  - ECADD:    address(0x06)
///  - ECMUL:    address(0x07)
///  - ECPAIRING address(0x08)
///  - Input encoding for G2 points in the pairing precompile requires reversing Fp2 coefficients.
///    This library follows the common convention where G2.X/Y are stored as [c0, c1] but encoded as [c1, c0].
library BN254 {
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /// @dev Fp2 element is represented as [c0, c1] corresponding to c0 + c1 * i.
    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    function P2() internal pure returns (G2Point memory) {
        return G2Point(
            [
                uint256(
                    10857046999023057135944570762232829481370756359578518086990519993285655852781
                ),
                uint256(
                    11559732032986387107991004021392285783925812861821192530917403151452391805634
                )
            ],
            [
                uint256(
                    8495653923123431417604973247489272438418190587263600148770280649306958101930
                ),
                uint256(
                    4082367875863433681332203403145435568316851327593401208105741076214120093531
                )
            ]
        );
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) {
            return G1Point(0, 0);
        }
        // y = -y mod q
        uint256 y = p.y % FIELD_MODULUS;
        return G1Point(p.x, y == 0 ? 0 : FIELD_MODULUS - y);
    }

    function ecAdd(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input = [p1.x, p1.y, p2.x, p2.y];
        bool ok;
        assembly {
            // call ecadd precompile (0x06)
            ok := staticcall(gas(), 0x06, input, 0x80, r, 0x40)
        }
        require(ok, "BN254: ecAdd failed");
    }

    function ecMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input = [p.x, p.y, s];
        bool ok;
        assembly {
            // call ecmul precompile (0x07)
            ok := staticcall(gas(), 0x07, input, 0x60, r, 0x40)
        }
        require(ok, "BN254: ecMul failed");
    }

    /// @notice Pairing check for arrays of points.
    /// @dev Returns true if product_i e(p1[i], p2[i]) == 1 in Fp12.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length, "BN254: length mismatch");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < elements; i++) {
            uint256 o = i * 6;
            input[o + 0] = p1[i].x;
            input[o + 1] = p1[i].y;
            // IMPORTANT: reverse Fp2 coefficients for the precompile encoding.
            input[o + 2] = p2[i].x[1];
            input[o + 3] = p2[i].x[0];
            input[o + 4] = p2[i].y[1];
            input[o + 5] = p2[i].y[0];
        }

        uint256[1] memory out;
        bool ok;
        assembly {
            // call pairing precompile (0x08)
            ok := staticcall(gas(), 0x08, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        }
        require(ok, "BN254: pairing call failed");
        return out[0] != 0;
    }

    function pairingProd2(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }

    function pairingProd3(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }

    function pairingProd4(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}
