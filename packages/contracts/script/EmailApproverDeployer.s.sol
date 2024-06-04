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

        address dkimRegistry =
            deploy("DKIMRegistry", bytes.concat(type(DKIMRegistry).creationCode, abi.encode(deployer)));
        writeAddressToEnv("DKIMRegistry", dkimRegistry);

        address emailApprover =
            deploy("EmailApprover", bytes.concat(type(EmailApprover).creationCode, abi.encode(dkimRegistry, verifier)));
        writeAddressToEnv("EmailApprover", emailApprover);

        address emailApproverFactory = deploy(
            "EmailApproverFactory ", bytes.concat(type(EmailApproverFactory).creationCode, abi.encode(emailApprover))
        );
        writeAddressToEnv("EmailApproverFactory", emailApproverFactory);
        // gmail.com
        DKIMRegistry(dkimRegistry).setDKIMPublicKeyHash(
            bytes32(uint256(19361475216702037345099198859178566376129780752330640287510661993072372998404)),
            bytes32(uint256(6632353713085157925504008443078919716322386156160602218536961028046468237192))
        );

        DKIMRegistry(dkimRegistry).setDKIMDomainName(
            bytes32(uint256(19361475216702037345099198859178566376129780752330640287510661993072372998404)), "gmail.com"
        );
    }
}
