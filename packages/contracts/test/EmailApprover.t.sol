// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {EmailApprover, DKIMRegistry, Groth16Verifier} from "../src/EmailApprover.sol";

contract EmailApproverTest is Test {
    Groth16Verifier public verifier;
    DKIMRegistry public registry;
    EmailApprover public emailApprover;

    function setUp() public {
        verifier = new Groth16Verifier();

        bytes32[] memory domainNameHashes = new bytes32[](1);
        domainNameHashes[
            0
        ] = 0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104;

        bytes32[] memory publicKeyHashes = new bytes32[](1);
        publicKeyHashes[
            0
        ] = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;

        registry = new DKIMRegistry(
            address(this),
            1 days,
            domainNameHashes,
            publicKeyHashes
        );

        // commit(xurigong@gmail.com, 12322)
        bytes32 senderCommitment = 0x3021da71aa1435b4be7ced3ba1ac8058a0d2c796007e8b0b95483912a9e3728e;

        // deploy at 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a
        address controlAddress = 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a;
        address _emailApprover = address(new EmailApprover(registry, verifier));
        // hack to bypass _disableInitializers
        vm.store(
            address(_emailApprover),
            0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00,
            bytes32(uint256(0))
        );
        EmailApprover(_emailApprover).initialize(senderCommitment);
        vm.etch(controlAddress, getCode(_emailApprover));
        emailApprover = EmailApprover(controlAddress);
    }

    function getCode(address addr) private view returns (bytes memory extcode) {
        assembly {
            let size := extcodesize(addr)
            extcode := mload(0x40)
            mstore(0x40, add(extcode, and(add(add(size, 32), 31), not(31))))
            mstore(extcode, size)
            extcodecopy(addr, add(extcode, 0x20), 0, size)
        }
    }

    function test_isValidSignature() public view {
        uint256[8] memory proof = [
            0x2817e92787efa427962b8f1fc163a8d1967b61de29ed2f8a7c33077660cd4de3,
            0x122ffc6c6e086a151e936c51e4eadc85b9765d79a787952979f1561d491b7b7d,
            0x1882a24d6b66e78df91c6f177c1f5d401f0394f184df61da935bb5ad3c571659,
            0x1810d00832bb68c589372df7b5b282e9e155b8c7fed793bbf8123db0b6c7394a,
            0x06c66aa32c38c231cb7ec9d9db7b6c68e73a4ba238bcdc20e2ee516c3701222c,
            0x1a64fb1c0cd94c62098a4b0d8a06999dd97f250f3f160f9e2b5900a748974b02,
            0x1b71eea0511cf779e882680229813f977ec694d3c2e81780c2aa34d967f0bc7d,
            0x2ce634b47ed9cc14d861cf6f2e9e15f2b4e960f59f1e7fff01cfb811be49cff0
        ];

        bytes32 approvedHash = 0x38aa871e9f0d65113cc34018b17050c3c00dea62a4eb345fdde7f5efd6f7c064;

        bytes32 pubkeyHash = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
        bytes32 senderDomainHash = 0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104;

        bytes memory signature = abi.encode(
            proof,
            pubkeyHash,
            senderDomainHash
        );
        bytes4 magicValue = emailApprover.isValidSignature(
            approvedHash,
            signature
        );
        assert(magicValue == 0x1626ba7e);
    }
}
