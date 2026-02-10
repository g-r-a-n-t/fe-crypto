// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

interface Vm {
    function ffi(string[] calldata commandInput) external returns (bytes memory);
    function readFile(string calldata path) external returns (string memory);
    function expectRevert() external;
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
