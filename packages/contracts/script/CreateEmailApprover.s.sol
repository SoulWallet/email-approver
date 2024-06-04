// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "./DeployHelper.sol";
import "@source/EmailApprover.sol";

contract CreateEmailApprover is Script, DeployHelper {
    function run() public {
        vm.startBroadcast(privateKey);
        Network network = getNetwork();
        string memory networkName = NetWorkLib.getNetworkName();
        deploy();
    }

    function deploy() private {
        address emailApprover = 0x2D4Ac4164aEee1c42B2a2E117B921b3530088BD8;
        uint256[8] memory proof = [
            0x6cfe94aef611650ff929b13f7d8bf50650c1b9d45cb0cf2fec1d5934baefe01,
            0x5793a5c6fbbb7b7dd988eaa28b4399c0a12e77ed094b44768a213e6b0819c68,
            0x2a0050971c36add2e7d3082230c061d322ec7372c022fe92191d803444f6f4fd,
            0x525f320e9fcb5f3b4d755bcce85ee8a744aeb4a782f14faf3618a8cee81f923,
            0xe3cf63ee39859d24920e82275f6c2440708001bbf8bb3ea5805c76003e55726,
            0x1e1b487e04d20112de6040577a071af027b5b160d4823eecd313f0a54db7f057,
            0x264cde99bbce13d8f68eddae7e30068a3a04e84211ab2944fd44ab16dc7d7ad2,
            0xc5637043d38dc000a1bfc417e51bc04b81c3b930838fa40401e51430805268e
        ];

        bytes32 approvedHash = 0x38aa871e9f0d65113cc34018b17050c3c00dea62a4eb345fdde7f5efd6f7c064;
        bytes32 pubkeyHash =
            bytes32(uint256(6632353713085157925504008443078919716322386156160602218536961028046468237192));
        bytes32 senderDomainHash =
            bytes32(uint256(19361475216702037345099198859178566376129780752330640287510661993072372998404));
        console.logBytes(abi.encode(proof, pubkeyHash, senderDomainHash, approvedHash));

        bytes memory signature = abi.encode(proof, pubkeyHash, senderDomainHash);
        EmailApprover(emailApprover).approve(proof, pubkeyHash, senderDomainHash, approvedHash);
        // bytes4 magicValue = EmailApprover(emailApprover).isValidSignature(approvedHash, signature);
    }
}
