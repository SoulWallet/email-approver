// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/EmailApprover.sol";
import "../src/Verifier.sol";
import "@zk-email/contracts/DKIMRegistry.sol";

contract EmailApproverTest is Test {
    EmailApprover public approver;

    function setUp() public {
        DKIMRegistry dkimRegistry = new DKIMRegistry();
        Groth16Verifier verifier = new Groth16Verifier();
        // commit(xurigong@gmail.com, 12322)
        bytes32 senderCommitment = bytes32(uint256(21770830330223450464430503989801104958781861536559456253001293349309810700942));
        // dkimRegistry.setDKIMPublicKeyHash(
        //     "gmail.com",
        //     bytes32(0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788)
        // );
        approver = new EmailApprover(dkimRegistry, verifier, senderCommitment);
        console.log("approver address", address(approver));
    }
    
    // This is the test for ./eml/example2.eml
    function testApprove() public {
        uint256[8] memory proof = [
            0x2cd97aee5881ee21ece68ed7cc8ecb1eebad98b948f5858194ba104168be0c3b,
            0x029eef34758e57ba6e62ba14243a9a3843144b0cbd436a53a8119462e9e5cc2f,
            0x15c613eecb030abe03b1e97f0875dc6402613a58815afe1b9e43a7dc49b993a7,
            0x1188bb9ad93aedec2a3294efceffff7ad5d8318318dfae9aa26aea765d034355,
            0x12773b3ed5e428b5b44258bdad616f06ab32e1aa1d37d8117ef94fc3ed424e50,
            0x2bc7145c1f36740924a2a627cc8731a388ae250c76237df9d7c88accf625eb49,
            0x2b97f8426f10dd1d86e4ca115e428049baa26f0e5519871ad96eda8a58984613,
            0x1a4ddbb8154e92b5c4abc0831d8653de485a2ae5bff10a5d73fa5b1e62a5c684
        ];
        bytes32 pubkeyHash = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
        bytes32 senderDomainHash = 0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104;
        bytes32 approvedHash = 0x38aa871e9f0d65113cc34018b17050c3c00dea62a4eb345fdde7f5efd6f7c064;

        approver.approve(proof, pubkeyHash, senderDomainHash, approvedHash);
        assert(approver.approved(approvedHash));
    }
}