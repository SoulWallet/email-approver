// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./interfaces/IDKIMRegistry.sol";

/**
 * This code is based on the zk email DKIMRegistry found at https://github.com/zkemail/zk-email-verify/blob/4a70031eb508a0b125729dd75be45632f2c3a8ae/packages/contracts/DKIMRegistry.sol
 * with slight modifications to the function paramaters and the event names.
 * Credit to the original authors and contributors.
 */
contract DKIMRegistry is IDKIMRegistry, Ownable {
    uint256 public immutable TIMELOCK_DELAY;

    constructor(
        address _signer,
        uint256 _timelockDelay,
        bytes32[] memory domainNameHashes,
        bytes32[] memory publicKeyHashes
    ) Ownable(_signer) {
        TIMELOCK_DELAY = _timelockDelay;
        require(domainNameHashes.length == publicKeyHashes.length, "invalid contructor data");
        for (uint256 i = 0; i < domainNameHashes.length; i++) {
            dkimPublicKeyHashes[domainNameHashes[i]][publicKeyHashes[i]] = true;
            emit DKIMPublicKeyHashRegistered(domainNameHashes[i], publicKeyHashes[i]);
        }
    }

    event DKIMPublicKeyHashRegistered(bytes32 domainNameHash, bytes32 publicKeyHash);
    event DKIMPublicKeyHashRevoked(bytes32 publicKeyHash);
    event DKIMDomainName(bytes32 domainNameHash, string domain);
    event DKIMPublicKeyHashScheduled(bytes32 domainNameHash, bytes32 publicKeyHash, uint256 executeTime);
    event DKIMPublicKeyHashesScheduled(bytes32 domainNameHash, bytes32[] publicKeyHashes, uint256 executeTime);
    event DKIMPublicKeyHashCanceled(bytes32 publicKeyHash);

    // Mapping from domain name to DKIM public key hash
    mapping(bytes32 => mapping(bytes32 => bool)) public dkimPublicKeyHashes;

    mapping(bytes32 => string) public domainName;

    // DKIM public that are revoked (eg: in case of private key compromise)
    mapping(bytes32 => bool) public revokedDKIMPublicKeyHashes;

    struct Timelock {
        bytes32 domainNameHash;
        bytes32 publicKeyHash;
        uint256 executeTime;
    }

    mapping(bytes32 => Timelock) public timelocks;

    function isDKIMPublicKeyHashValid(bytes32 domainNameHash, bytes32 publicKeyHash) public view returns (bool) {
        if (revokedDKIMPublicKeyHashes[publicKeyHash]) {
            return false;
        }

        if (dkimPublicKeyHashes[domainNameHash][publicKeyHash]) {
            return true;
        }

        return false;
    }

    function setDKIMDomainName(bytes32 domainNameHash, string memory domain) public onlyOwner {
        domainName[domainNameHash] = domain;
        emit DKIMDomainName(domainNameHash, domain);
    }

    function scheduleSetDKIMPublicKeyHash(bytes32 domainNameHash, bytes32 publicKeyHash) public onlyOwner {
        require(dkimPublicKeyHashes[domainNameHash][publicKeyHash] == false, "already registered");
        require(!revokedDKIMPublicKeyHashes[publicKeyHash], "cannot set revoked pubkey");
        require(timelocks[publicKeyHash].executeTime == 0, "already scheduled");
        uint256 executeTime = block.timestamp + TIMELOCK_DELAY;
        timelocks[publicKeyHash] = Timelock(domainNameHash, publicKeyHash, executeTime);
        emit DKIMPublicKeyHashScheduled(domainNameHash, publicKeyHash, executeTime);
    }

    function executeSetDKIMPublicKeyHash(bytes32 publicKeyHash) public onlyOwner {
        Timelock memory timelock = timelocks[publicKeyHash];
        require(timelock.executeTime > 0, "no scheduled operation");
        require(block.timestamp >= timelock.executeTime, "too early to execute");

        dkimPublicKeyHashes[timelock.domainNameHash][publicKeyHash] = true;
        delete timelocks[publicKeyHash];

        emit DKIMPublicKeyHashRegistered(timelock.domainNameHash, publicKeyHash);
    }

    function cancelSetDKIMPublicKeyHash(bytes32 publicKeyHash) public onlyOwner {
        Timelock memory timelock = timelocks[publicKeyHash];
        require(timelock.executeTime > 0, "no scheduled operation");

        delete timelocks[publicKeyHash];

        emit DKIMPublicKeyHashCanceled(publicKeyHash);
    }

    function scheduleSetDKIMPublicKeyHashes(bytes32 domainNameHash, bytes32[] memory publicKeyHashes)
        public
        onlyOwner
    {
        for (uint256 i = 0; i < publicKeyHashes.length; i++) {
            scheduleSetDKIMPublicKeyHash(domainNameHash, publicKeyHashes[i]);
        }

        uint256 executeTime = block.timestamp + TIMELOCK_DELAY;
        emit DKIMPublicKeyHashesScheduled(domainNameHash, publicKeyHashes, executeTime);
    }

    function revokeDKIMPublicKeyHash(bytes32 publicKeyHash) public onlyOwner {
        revokedDKIMPublicKeyHashes[publicKeyHash] = true;
        emit DKIMPublicKeyHashRevoked(publicKeyHash);
    }
}
