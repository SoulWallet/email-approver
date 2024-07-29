// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "./DeployHelper.sol";
import "@source/DKIMRegistry.sol";
import "@source/EmailApproverFactory.sol";
import "@source/EmailApprover.sol";
import "@source/Verifier.sol";

contract EmailApproverDeployer is Script, DeployHelper {
    function run() public {
        vm.startBroadcast(privateKey);
        Network network = getNetwork();
        string memory networkName = NetWorkLib.getNetworkName();
        console.log("deploy email approver contract on ", networkName);
        deploy();
    }

    function deploy() private {
        address verifier = deploy("Verifier", type(Groth16Verifier).creationCode);
        writeAddressToEnv("VERIFIER", verifier);
        // gmail.com
        bytes32 gmailDomainNameHash = 0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104;
        bytes32 gmailPublicKeyHash = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
        // yahoo.com
        bytes32 yahooDomainNameHash = 0x2b5810b6a2491df10e753184b8130cf794eaa2523e5c7506c2d2056963455b11;
        bytes32 yahooPublicKeyHash = 0x0ab563b6afca637f6a74620d5bb89433e74d705766145b1637ae0642cf97bcd4;
        // icloud.com
        bytes32 icloudDomainNameHash = 0x27b9e2f36b240bc7ce077dccf55a60887aa8d7a82f50b1f0cc5c67a47a90098a;
        bytes32 icloudPublicKeyHash = 0x183a285cf45254a83af897c5f92f25f0527b28677a020fb397ea2b6c7b317c4c;

        // icloud.com
        bytes32 icloudDomainNameHash2 = 0x27b9e2f36b240bc7ce077dccf55a60887aa8d7a82f50b1f0cc5c67a47a90098a;
        bytes32 icloudPublicKeyHash2 = 0x2dd9fd991d7c5fabe0f1829f236cc7d907a8d232f6091aa7bdb996d14c1f9570;

        // aol.com
        bytes32 aolDomainNameHash = 0x0ce6f6a514c48a9ce37238d341a9832eb9f5d706e8235b0b349589da805116ab;
        bytes32 aolPublicKeyHash = 0x024dcc49ea2197c020ae7f479924cbfdf1fdc3c28ab65ce43751b1c4c71180e2;

        // protonmail.com
        bytes32 protonDomainNameHash = 0x16715a47dbe53d86b4044828e9570091df401d2fb31d2d705d3ccb67af15a9d3;
        bytes32 protonPublicKeyHash = 0x2c1a832b04c5f0eb822f05c10cdb67f6a2fc0896d33a7458005039c748aaf54c;

        bytes32[] memory domainNameHashes = new bytes32[](6);
        domainNameHashes[0] = gmailDomainNameHash;
        domainNameHashes[1] = yahooDomainNameHash;
        domainNameHashes[2] = icloudDomainNameHash;
        domainNameHashes[3] = icloudDomainNameHash2;
        domainNameHashes[4] = aolDomainNameHash;
        domainNameHashes[5] = protonDomainNameHash;

        bytes32[] memory publicKeyHashes = new bytes32[](6);
        publicKeyHashes[0] = gmailPublicKeyHash;
        publicKeyHashes[1] = yahooPublicKeyHash;
        publicKeyHashes[2] = icloudPublicKeyHash;
        publicKeyHashes[3] = icloudPublicKeyHash2;
        publicKeyHashes[4] = aolPublicKeyHash;
        publicKeyHashes[5] = protonPublicKeyHash;

        address dkimRegistry = deploy(
            "DKIMRegistry",
            bytes.concat(
                type(DKIMRegistry).creationCode, abi.encode(deployer, 1 days, domainNameHashes, publicKeyHashes)
            )
        );
        writeAddressToEnv("DKIMRegistry", dkimRegistry);

        address emailApprover =
            deploy("EmailApprover", bytes.concat(type(EmailApprover).creationCode, abi.encode(dkimRegistry, verifier)));
        writeAddressToEnv("EmailApprover", emailApprover);

        address emailApproverFactory = deploy(
            "EmailApproverFactory ", bytes.concat(type(EmailApproverFactory).creationCode, abi.encode(emailApprover))
        );
        writeAddressToEnv("EmailApproverFactory", emailApproverFactory);
        DKIMRegistry(dkimRegistry).setDKIMDomainName(
            0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104, "gmail.com"
        );

        DKIMRegistry(dkimRegistry).setDKIMDomainName(
            0x2b5810b6a2491df10e753184b8130cf794eaa2523e5c7506c2d2056963455b11, "yahoo.com"
        );
        DKIMRegistry(dkimRegistry).setDKIMDomainName(
            0x27b9e2f36b240bc7ce077dccf55a60887aa8d7a82f50b1f0cc5c67a47a90098a, "icloud.com"
        );
        DKIMRegistry(dkimRegistry).setDKIMDomainName(
            0x0ce6f6a514c48a9ce37238d341a9832eb9f5d706e8235b0b349589da805116ab, "aol.com"
        );
        DKIMRegistry(dkimRegistry).setDKIMDomainName(
            0x16715a47dbe53d86b4044828e9570091df401d2fb31d2d705d3ccb67af15a9d3, "protonmail.com"
        );
    }
}
