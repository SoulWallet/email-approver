// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {DKIMRegistry} from "../src/EmailApprover.sol";

contract DKIMRegistryTest is Test {
    DKIMRegistry public registry;
    bytes32 public defaultDomainNameHash = 0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104;
    bytes32 public defaultPublicKeyHash = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;

    function setUp() public {
        bytes32[] memory domainNameHashes = new bytes32[](1);
        domainNameHashes[0] = defaultDomainNameHash;

        bytes32[] memory publicKeyHashes = new bytes32[](1);
        publicKeyHashes[0] = defaultPublicKeyHash;

        registry = new DKIMRegistry(address(this), 1 days, domainNameHashes, publicKeyHashes);
    }

    function test_setDKIMRecord() public {
        bytes32 publicKeyHash = 0x1ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;

        registry.scheduleSetDKIMPublicKeyHash(defaultDomainNameHash, publicKeyHash);
        assertEq(registry.isDKIMPublicKeyHashValid(defaultDomainNameHash, publicKeyHash), false);
        vm.expectRevert("too early to execute");
        registry.executeSetDKIMPublicKeyHash(publicKeyHash);
        vm.warp(block.timestamp + 1 days);
        registry.executeSetDKIMPublicKeyHash(publicKeyHash);
        assertEq(registry.isDKIMPublicKeyHashValid(defaultDomainNameHash, publicKeyHash), true);
    }

    function test_cancelDKIMRecord() public {
        bytes32 publicKeyHash = 0x1ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;

        registry.scheduleSetDKIMPublicKeyHash(defaultDomainNameHash, publicKeyHash);
        assertEq(registry.isDKIMPublicKeyHashValid(defaultDomainNameHash, publicKeyHash), false);
        vm.expectRevert("too early to execute");
        registry.executeSetDKIMPublicKeyHash(publicKeyHash);
        registry.cancelSetDKIMPublicKeyHash(publicKeyHash);
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert("no scheduled operation");
        registry.executeSetDKIMPublicKeyHash(publicKeyHash);
        assertEq(registry.isDKIMPublicKeyHashValid(defaultDomainNameHash, publicKeyHash), false);
    }

    function test_duplicateDKIMRecord() public {
        vm.expectRevert("already registered");
        registry.scheduleSetDKIMPublicKeyHash(defaultDomainNameHash, defaultPublicKeyHash);
    }

    function test_revokeDKIMRecord() public {
        registry.revokeDKIMPublicKeyHash(0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788);
        assertEq(registry.isDKIMPublicKeyHashValid(defaultDomainNameHash, defaultPublicKeyHash), false);
    }
}
