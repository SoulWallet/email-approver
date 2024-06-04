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
    constructor(address _signer) Ownable(_signer) {}

    event DKIMPublicKeyHashRegistered(bytes32 domainNameHash, bytes32 publicKeyHash);
    event DKIMPublicKeyHashRevoked(bytes32 publicKeyHash);
    event DKIMDomainName(bytes32 domainNameHash, string domain);

    // Mapping from domain name to DKIM public key hash
    mapping(bytes32 => mapping(bytes32 => bool)) public dkimPublicKeyHashes;

    mapping(bytes32 => string) public domainName;

    // DKIM public that are revoked (eg: in case of private key compromise)
    mapping(bytes32 => bool) public revokedDKIMPublicKeyHashes;

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

    function setDKIMPublicKeyHash(bytes32 domainNameHash, bytes32 publicKeyHash) public onlyOwner {
        require(!revokedDKIMPublicKeyHashes[publicKeyHash], "cannot set revoked pubkey");

        dkimPublicKeyHashes[domainNameHash][publicKeyHash] = true;

        emit DKIMPublicKeyHashRegistered(domainNameHash, publicKeyHash);
    }

    function setDKIMPublicKeyHashes(bytes32 domainNameHash, bytes32[] memory publicKeyHashes) public onlyOwner {
        for (uint256 i = 0; i < publicKeyHashes.length; i++) {
            setDKIMPublicKeyHash(domainNameHash, publicKeyHashes[i]);
        }
    }

    function revokeDKIMPublicKeyHash(bytes32 publicKeyHash) public onlyOwner {
        revokedDKIMPublicKeyHashes[publicKeyHash] = true;
        emit DKIMPublicKeyHashRevoked(publicKeyHash);
    }
}
