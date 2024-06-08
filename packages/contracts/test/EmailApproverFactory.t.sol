// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {EmailApprover, DKIMRegistry, Groth16Verifier} from "../src/EmailApprover.sol";
import {EmailApproverFactory} from "../src/EmailApproverFactory.sol";

contract EmailApproverFactoryTest is Test {
    Groth16Verifier public verifier;
    DKIMRegistry public registry;
    EmailApprover public emailApprover;
    EmailApproverFactory public emailApproverFactory;

    function setUp() public {
        verifier = new Groth16Verifier();
        bytes32[] memory domainNameHashes = new bytes32[](1);
        domainNameHashes[0] = 0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104;

        bytes32[] memory publicKeyHashes = new bytes32[](1);
        publicKeyHashes[0] = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;

        registry = new DKIMRegistry(address(this), 1 days, domainNameHashes, publicKeyHashes);

        address _emailApprover = address(new EmailApprover(registry, verifier));
        emailApproverFactory = new EmailApproverFactory(_emailApprover);
    }

    function test_createNewApprover() public {
        bytes32 senderCommitment = 0x3021da71aa1435b4be7ced3ba1ac8058a0d2c796007e8b0b95483912a9e3728e;
        address newApprover = emailApproverFactory.createEmailApprover(senderCommitment, bytes32(0));
        (DKIMRegistry _registry, Groth16Verifier _verifier, bytes32 _senderCommitment) =
            EmailApprover(newApprover).getEmailApproverInfo();
        assertEq(address(_registry), address(registry));
        assertEq(address(_verifier), address(verifier));
        assertEq(_senderCommitment, senderCommitment);
    }
}
