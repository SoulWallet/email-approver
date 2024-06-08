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
        bytes32 gmailDomainNameHash =
            bytes32(uint256(19361475216702037345099198859178566376129780752330640287510661993072372998404));
        bytes32 gmailPublicKeyHash =
            bytes32(uint256(6632353713085157925504008443078919716322386156160602218536961028046468237192));
        bytes32[] memory domainNameHashes = new bytes32[](1);
        domainNameHashes[0] = gmailDomainNameHash;

        bytes32[] memory publicKeyHashes = new bytes32[](1);
        publicKeyHashes[0] = gmailPublicKeyHash;

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
            bytes32(uint256(19361475216702037345099198859178566376129780752330640287510661993072372998404)), "gmail.com"
        );
    }
}
