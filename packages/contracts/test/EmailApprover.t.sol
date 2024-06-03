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
        registry = new DKIMRegistry(address(this));

        // commit(xurigong@gmail.com, 12322)
        bytes32 senderCommitment = 0x3021da71aa1435b4be7ced3ba1ac8058a0d2c796007e8b0b95483912a9e3728e;

        // deploy at 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a
        address controlAddress = 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a;
        address _emailApprover = address(
            new EmailApprover(registry, verifier, senderCommitment)
        );
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
            0x016576e2692e19de84b096d16db8cec5b74828cde3a75d03d02f11ea82e604d3,
            0x1e4b16307377e52cc9d3b644014b4c21f2800c2eafda1bb22e961a9dcc448581,
            0x289b24836918a2fd2f302e677e575216bba69e70a7343b5ba810b2df78a65f43,
            0x073b279836e73efc9534c1fda906b16d6f176ec37fc8ca2201fe38a50e5eb441,
            0x2dff3a37fe8bf88826e2697c5f4d1e650e2f885b48ae3694f6a9e2b33c4c2d1a,
            0x2061f6acc8a7b2128af90fcb7757a1eef625987ffeaf5ba5f0bfe3d9308deda9,
            0x1cfa9b5af2443b7b06c89f1745c6aff2d52a858aff5f9d444bf4fcef00d577fa,
            0x2a9f6c250e5fada6d25f86b1fa1637317d2d68094a06cfb12d9aff1f99de23fa
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
