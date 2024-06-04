// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IDKIMRegistry {
    function isDKIMPublicKeyHashValid(bytes32 domainHash, bytes32 publicKeyHash) external view returns (bool);
}
