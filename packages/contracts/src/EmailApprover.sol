// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@zk-email/contracts/DKIMRegistry.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { Groth16Verifier } from "./Verifier.sol";


contract EmailApprover is IERC1271  {
    event Approved(bytes32 hash);

    DKIMRegistry public dkimRegistry;
    Groth16Verifier public verifier;
    mapping(bytes32 => bool) public approved;
    bytes32 public senderCommitment;

    constructor(DKIMRegistry registry, Groth16Verifier _verifier, bytes32 _senderCommitment) {
        dkimRegistry = registry;
        verifier = _verifier;
        senderCommitment = _senderCommitment;
    }
    
    function _isValidProof(uint256[8] memory proof, bytes32 pubkeyHash, bytes32 senderDomainHash, bytes32 approvedHash) internal view returns (bool) {
        // 1. Verify DKIM key
        // Note: this currently is not compitable with the current DKIMRegistry
        // require(dkimRegistry.isDKIMPublicKeyHashValid(senderDomainHash, pubkeyHash), "invalid dkim signature");
        
        uint256[6] memory signals;
        signals[0] = uint256(pubkeyHash);
        signals[1] = uint256(senderDomainHash);
        signals[2] = uint256(senderCommitment);
        signals[3] = uint256(uint160(address(this)));
        // split bytes32 hash into two parts
        signals[4] = uint256(approvedHash) >> 128;
        signals[5] = uint256(approvedHash) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        // Verify Dkim proof
        return verifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            signals
        );
    }

    function approve(uint256[8] memory proof, bytes32 pubkeyHash, bytes32 senderDomainHash, bytes32 approvedHash) public {
        require(!approved[approvedHash], "already approved");
        require(_isValidProof(proof, pubkeyHash, senderDomainHash, approvedHash), "invalid proof");

        approved[approvedHash] = true;
        emit Approved(approvedHash);
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue) {
        if (signature.length == 0) {
            return approved[hash] ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
        }

        // decode signature
        (uint256[8] memory proof, bytes32 pubkeyHash, bytes32 senderDomainHash, bytes32 approvedHash) =
            abi.decode(signature, (uint256[8], bytes32, bytes32, bytes32));
        return _isValidProof(proof, pubkeyHash, senderDomainHash, approvedHash) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
