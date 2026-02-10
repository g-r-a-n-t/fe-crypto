// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Groth16Bn254VerifierReference} from "./ref/Groth16Bn254VerifierReference.sol";
import {BN254} from "./ref/BN254.sol";

interface Vm {
    function ffi(string[] calldata commandInput) external returns (bytes memory);
    function readFile(string calldata path) external returns (string memory);
    function expectRevert() external;
    function assume(bool condition) external;
    function pauseGasMetering() external;
    function resumeGasMetering() external;
}

interface IGroth16Bn254Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[1] calldata input
    ) external view returns (bool);
}

contract Groth16Bn254VerifierTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // SNARK scalar field for BN254 (a.k.a. Fr modulus).
    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IGroth16Bn254Verifier private verifier;
    IGroth16Bn254Verifier private referenceVerifier;

    function setUp() public {
        string[] memory cmd = new string[](7);
        cmd[0] = "fe";
        cmd[1] = "build";
        cmd[2] = "--out-dir";
        cmd[3] = "out/fe";
        cmd[4] = "--contract";
        cmd[5] = "Groth16Bn254Verifier";
        cmd[6] = "./verifiers";
        vm.ffi(cmd);

        bytes memory deployCode = _hexStringToBytes(vm.readFile("out/fe/Groth16Bn254Verifier.bin"));
        verifier = IGroth16Bn254Verifier(_deploy(deployCode));
        referenceVerifier = IGroth16Bn254Verifier(address(new Groth16Bn254VerifierReference()));
    }

    function test_verifyProof_ok() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        bool ok = verifier.verifyProof(a, b, c, input);
        assert(ok);
    }

    function test_referenceVerifier_verifyProof_ok() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        bool ok = referenceVerifier.verifyProof(a, b, c, input);
        assert(ok);
    }

    function test_diff_verifyProof_matchesReference_onDemoProof() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        bool okFe = verifier.verifyProof(a, b, c, input);
        bool okRef = referenceVerifier.verifyProof(a, b, c, input);
        assert(okFe == okRef);
    }

    function test_verifyProof_returnsFalse_onWrongPublicInput() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        input[0] = 0x22;
        bool ok = verifier.verifyProof(a, b, c, input);
        assert(!ok);
    }

    function test_diff_verifyProof_swappedBLimbs_matchesReference() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        // The verifier expects `b` in precompile order `[[x_c1,x_c0],[y_c1,y_c0]]`.
        // Swapping limbs converts it to the more "math-y" `[[x_c0,x_c1],[y_c0,y_c1]]` order, which
        // should not verify for a real proof (it may return `false` or revert due to invalid points).
        uint256[2][2] memory swapped = [[b[0][1], b[0][0]], [b[1][1], b[1][0]]];

        (bool okFe, bool resFe) = _staticcallVerifyProof(address(verifier), a, swapped, c, input);
        (bool okRef, bool resRef) = _staticcallVerifyProof(address(referenceVerifier), a, swapped, c, input);

        assert(okFe == okRef);
        if (okFe) {
            assert(resFe == resRef);
            assert(!resFe);
        }
    }

    function test_verifyProof_reverts_onOutOfRangePublicInput() public {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        input[0] = SNARK_SCALAR_FIELD;
        vm.expectRevert();
        verifier.verifyProof(a, b, c, input);
    }

    function test_bn254_pairingProd2_generator_cancels() public view {
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        bool ok = BN254.pairingProd2(g1, g2, BN254.negate(g1), g2);
        assert(ok);
    }

    function test_diff_verifyProof_reverts_onOutOfRangePublicInput() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        input[0] = SNARK_SCALAR_FIELD;
        (bool okFe, ) = _staticcallVerifyProof(address(verifier), a, b, c, input);
        (bool okRef, ) = _staticcallVerifyProof(address(referenceVerifier), a, b, c, input);
        assert(!okFe);
        assert(!okRef);
    }

    function test_diff_verifyProof_maxInRangePublicInput_doesNotRevert() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        input[0] = SNARK_SCALAR_FIELD - 1;

        (bool okFe, bool resFe) = _staticcallVerifyProof(address(verifier), a, b, c, input);
        (bool okRef, bool resRef) = _staticcallVerifyProof(address(referenceVerifier), a, b, c, input);
        assert(okFe && okRef);
        assert(resFe == resRef);
    }

    function testFuzz_diff_verifyProof_raw(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256 publicInput
    ) public view {
        uint256[1] memory input = [publicInput];

        (bool okFe, bool resFe) = _staticcallVerifyProof(address(verifier), a, b, c, input);
        (bool okRef, bool resRef) = _staticcallVerifyProof(address(referenceVerifier), a, b, c, input);

        require(okFe == okRef, "DIFF: call status");
        if (okFe) {
            require(resFe == resRef, "DIFF: result");
        }
    }

    function testFuzz_diff_verifyProof_inRange(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256 publicInput
    ) public {
        vm.assume(publicInput < SNARK_SCALAR_FIELD);
        uint256[1] memory input = [publicInput];

        (bool okFe, bool resFe) = _staticcallVerifyProof(address(verifier), a, b, c, input);
        (bool okRef, bool resRef) = _staticcallVerifyProof(address(referenceVerifier), a, b, c, input);

        require(okFe == okRef, "DIFF: call status");
        if (okFe) {
            require(resFe == resRef, "DIFF: result");
        }
    }

    function testFuzz_diff_verifyProof_validG1Points(
        uint256 aScalar,
        uint256 cScalar,
        uint256 publicInputRaw,
        uint8 bChoice
    ) public view {
        uint256 publicInput = publicInputRaw % SNARK_SCALAR_FIELD;

        BN254.G1Point memory A = BN254.ecMul(BN254.P1(), aScalar % SNARK_SCALAR_FIELD);
        BN254.G1Point memory C = BN254.ecMul(BN254.P1(), cScalar % SNARK_SCALAR_FIELD);

        uint256[2] memory a = [A.x, A.y];
        uint256[2] memory c = [C.x, C.y];
        uint256[2][2] memory b = _validB(bChoice);
        uint256[1] memory input = [publicInput];

        (bool okFe, bool resFe) = _staticcallVerifyProof(address(verifier), a, b, c, input);
        (bool okRef, bool resRef) = _staticcallVerifyProof(address(referenceVerifier), a, b, c, input);

        require(okFe && okRef, "DIFF: unexpected revert");
        require(resFe == resRef, "DIFF: result");
    }

    function testGas_bench_fe_verifyProof_ok() public {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        vm.pauseGasMetering();
        bytes memory callData = abi.encodeWithSelector(IGroth16Bn254Verifier.verifyProof.selector, a, b, c, input);
        vm.resumeGasMetering();

        (bool ok, bool res) = _staticcallBool(address(verifier), callData);

        vm.pauseGasMetering();
        require(ok && res, "FE: demo proof should verify");
    }

    function testGas_bench_solidity_verifyProof_ok() public {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();

        vm.pauseGasMetering();
        bytes memory callData = abi.encodeWithSelector(IGroth16Bn254Verifier.verifyProof.selector, a, b, c, input);
        vm.resumeGasMetering();

        (bool ok, bool res) = _staticcallBool(address(referenceVerifier), callData);

        vm.pauseGasMetering();
        require(ok && res, "Solidity: demo proof should verify");
    }

    function testGas_bench_fe_verifyProof_wrongPublicInput() public {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();
        input[0] = 0x22;

        vm.pauseGasMetering();
        bytes memory callData = abi.encodeWithSelector(IGroth16Bn254Verifier.verifyProof.selector, a, b, c, input);
        vm.resumeGasMetering();

        (bool ok, bool res) = _staticcallBool(address(verifier), callData);

        vm.pauseGasMetering();
        require(ok && !res, "FE: wrong input should not verify");
    }

    function testGas_bench_solidity_verifyProof_wrongPublicInput() public {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[1] memory input
        ) = _demoProof();
        input[0] = 0x22;

        vm.pauseGasMetering();
        bytes memory callData = abi.encodeWithSelector(IGroth16Bn254Verifier.verifyProof.selector, a, b, c, input);
        vm.resumeGasMetering();

        (bool ok, bool res) = _staticcallBool(address(referenceVerifier), callData);

        vm.pauseGasMetering();
        require(ok && !res, "Solidity: wrong input should not verify");
    }

    function _demoProof()
        private
        pure
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[1] memory input)
    {
        a = [
            uint256(0x28930e0aeb50e7e3b5f9a54a6abdce99978e00701914dfd4d87f8dc5ea9e1d02),
            uint256(0x02c1e99774e679c144aceac4e9fdbc67dc858533d9f49c5933939c89010131b7)
        ];

        // b is provided in precompile order: [[x_c1, x_c0], [y_c1, y_c0]]
        b = [
            [
                uint256(0x0684d8357689fb95e886a8251db0e142ffdda8032e314750455b9f5ff13159ca),
                uint256(0x26189ebc171412019704e808c432062721db66c4a22635f20ed422a2147ad5bf)
            ],
            [
                uint256(0x005d309291fd34bef6248c17779114907b6d912a5a02ddae46d902dbd05e2e1c),
                uint256(0x01673b4a2e94569e28e23a9ae808b9f92b4d21beca07522f79d16ec419a6e85c)
            ]
        ];

        c = [
            uint256(0x25170145c09315e2df3c93d155b39df35434469607b0121a16125224190a596a),
            uint256(0x05467081343913d54408694735a8d149578e7cbb3168f2b4283a7fe2861a7a42)
        ];

        input = [uint256(0x21)];
    }

    function _validB(uint8 choice) private pure returns (uint256[2][2] memory b) {
        uint8 c = choice % 5;

        // 0: Use the demo proof's B.
        if (c == 0) {
            (, b, , ) = _demoProof();
            return b;
        }

        // 1: verifying_key_beta2 (precompile order).
        if (c == 1) {
            b = [
                [
                    uint256(9138224228407402916103338031673805059436445969293455575712717090470338056266),
                    uint256(18390029660978007887012397144274200115548124992262045309168725395291020532646)
                ],
                [
                    uint256(13521623794085633987820957758529862860973247929283590310564032250223240671848),
                    uint256(3861004002262797311682051645188776069221901493726904234127961112799581415639)
                ]
            ];
            return b;
        }

        // 2: verifying_key_gamma2 (precompile order).
        if (c == 2) {
            b = [
                [
                    uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
                    uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781)
                ],
                [
                    uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
                    uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)
                ]
            ];
            return b;
        }

        // 3: verifying_key_delta2 (precompile order).
        if (c == 3) {
            b = [
                [
                    uint256(3810475614507152687978045945018363916901751186873297176897861851851025646174),
                    uint256(11517822973057293310299905404808144348048624735019551898183051528663733638390)
                ],
                [
                    uint256(7205787144229011189765531580637096098035200993493430523391610777645930427053),
                    uint256(18901678484212115678597129685298885730350402277813795965474832351751410499421)
                ]
            ];
            return b;
        }

        // 4: BN254 G2 generator (precompile order).
        BN254.G2Point memory p2 = BN254.P2();
        b = [[p2.x[1], p2.x[0]], [p2.y[1], p2.y[0]]];
    }

    function _staticcallVerifyProof(
        address target,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory input
    ) private view returns (bool ok, bool result) {
        (bool success, bytes memory data) = target.staticcall(
            abi.encodeWithSelector(IGroth16Bn254Verifier.verifyProof.selector, a, b, c, input)
        );
        if (!success) {
            return (false, false);
        }
        if (data.length != 32) {
            return (false, false);
        }
        return (true, abi.decode(data, (bool)));
    }

    function _staticcallBool(address target, bytes memory callData) private view returns (bool ok, bool result) {
        uint256 out;
        assembly ("memory-safe") {
            ok := staticcall(gas(), target, add(callData, 0x20), mload(callData), 0x00, 0x20)
            out := mload(0x00)
        }

        return (ok, ok && out != 0);
    }

    function _deploy(bytes memory creationCode) private returns (address deployed) {
        assembly ("memory-safe") {
            deployed := create(0, add(creationCode, 0x20), mload(creationCode))
        }
        require(deployed != address(0), "DEPLOY_FAILED");
    }

    function _hexStringToBytes(string memory s) private pure returns (bytes memory) {
        bytes memory strBytes = bytes(s);
        uint256 start = 0;
        uint256 end = strBytes.length;

        while (start < end && _isWhitespace(strBytes[start])) {
            start++;
        }
        while (end > start && _isWhitespace(strBytes[end - 1])) {
            end--;
        }

        if (end >= start + 2 && strBytes[start] == 0x30 && (strBytes[start + 1] == 0x78 || strBytes[start + 1] == 0x58)) {
            start += 2;
        }

        uint256 hexLen = end - start;
        require(hexLen % 2 == 0, "HEX_ODD_LENGTH");

        bytes memory out = new bytes(hexLen / 2);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = bytes1((_fromHexChar(strBytes[start + 2 * i]) << 4) | _fromHexChar(strBytes[start + 2 * i + 1]));
        }
        return out;
    }

    function _isWhitespace(bytes1 c) private pure returns (bool) {
        return c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d;
    }

    function _fromHexChar(bytes1 c) private pure returns (uint8) {
        uint8 b = uint8(c);
        if (b >= 48 && b <= 57) {
            return b - 48;
        }
        if (b >= 65 && b <= 70) {
            return b - 55;
        }
        if (b >= 97 && b <= 102) {
            return b - 87;
        }
        revert("HEX_BAD_CHAR");
    }
}
