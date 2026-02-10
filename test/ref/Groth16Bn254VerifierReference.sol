// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {BN254} from "./BN254.sol";

/// @title Groth16 BN254 reference verifier (demo VK)
/// @notice Solidity reference implementation used for differential fuzzing vs the Fe verifier.
/// @dev Verifying key constants mirror `verifiers/src/groth16_bn254.fe`.
contract Groth16Bn254VerifierReference {
    // SNARK scalar field for BN254 (a.k.a. Fr modulus).
    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function verifyingKeyAlpha1() internal pure returns (BN254.G1Point memory) {
        return
            BN254.G1Point(
                18986994054831033570197018374507745079604334824038474376810821382341658341358,
                9857034825708937828129722307559364555144967863984840417006236609097843967147
            );
    }

    function verifyingKeyBeta2() internal pure returns (BN254.G2Point memory) {
        return
            BN254.G2Point(
                [
                    uint256(
                        18390029660978007887012397144274200115548124992262045309168725395291020532646
                    ),
                    uint256(
                        9138224228407402916103338031673805059436445969293455575712717090470338056266
                    )
                ],
                [
                    uint256(
                        3861004002262797311682051645188776069221901493726904234127961112799581415639
                    ),
                    uint256(
                        13521623794085633987820957758529862860973247929283590310564032250223240671848
                    )
                ]
            );
    }

    function verifyingKeyGamma2() internal pure returns (BN254.G2Point memory) {
        return
            BN254.G2Point(
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

    function verifyingKeyDelta2() internal pure returns (BN254.G2Point memory) {
        return
            BN254.G2Point(
                [
                    uint256(
                        11517822973057293310299905404808144348048624735019551898183051528663733638390
                    ),
                    uint256(
                        3810475614507152687978045945018363916901751186873297176897861851851025646174
                    )
                ],
                [
                    uint256(
                        18901678484212115678597129685298885730350402277813795965474832351751410499421
                    ),
                    uint256(
                        7205787144229011189765531580637096098035200993493430523391610777645930427053
                    )
                ]
            );
    }

    function verifyingKeyIC(uint256 i) internal pure returns (BN254.G1Point memory) {
        if (i == 0) {
            return
                BN254.G1Point(
                    67521893739652156791009141370073344821154292280368295170345470354897934196,
                    17040597570089860980787757123222393819903832599488360597826421841263128988811
                );
        }
        if (i == 1) {
            return
                BN254.G1Point(
                    6621938124027639260974226744038109301855429178070752528844179929793898435285,
                    2291636765942087387769041560925446553420342985960064087254817725377189124295
                );
        }
        revert("Groth16: bad IC index");
    }

    /// @notice Verify a Groth16 proof against the demo verifying key.
    /// @dev `b` is provided in pairing-precompile order: `[[x_c1, x_c0], [y_c1, y_c0]]`.
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[1] calldata input
    ) external view returns (bool) {
        if (input[0] >= SNARK_SCALAR_FIELD) {
            revert("Groth16: input out of range");
        }

        BN254.G1Point memory A = BN254.G1Point(a[0], a[1]);
        BN254.G2Point memory B = BN254.G2Point([b[0][1], b[0][0]], [b[1][1], b[1][0]]);
        BN254.G1Point memory C = BN254.G1Point(c[0], c[1]);

        // vk_x = IC[0] + input[0] * IC[1]
        BN254.G1Point memory vk_x = BN254.ecAdd(verifyingKeyIC(0), BN254.ecMul(verifyingKeyIC(1), input[0]));

        return
            BN254.pairingProd4(
                BN254.negate(A),
                B,
                verifyingKeyAlpha1(),
                verifyingKeyBeta2(),
                vk_x,
                verifyingKeyGamma2(),
                C,
                verifyingKeyDelta2()
            );
    }
}

