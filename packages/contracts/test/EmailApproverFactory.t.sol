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
        registry = new DKIMRegistry(address(this));

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
