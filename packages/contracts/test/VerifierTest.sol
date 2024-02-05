// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/Verifier.sol";

contract VerifierTest is Test {
    Groth16Verifier public verifier;

    function setUp() public {
        verifier = new Groth16Verifier();
    }

    // This is the test for ./eml/example1.eml
    function testVerify() public {
        uint256[2] memory proof_a = [
            uint256(0x11450e8d4aeaf5f95d36a825efcb1a1ffb04068f6bc2ee8a3c7f4063c9287728),
            uint256(0x050990c844a7174ef37053b611de63fbf76b38dd501a34ec0295ac94844b4510)
            ];
        uint256[2][2] memory proof_b = [[uint256(0x2720fcda57449391e2d64f63e55b526e6e3fa91dd5017b3b8085cb00d3c9294f),
        uint256(0x107de9ae28976ead6702e275dc6973e2437df0079cb926e3709ac4cf432340c1)
        ],
        [uint256(0x15cc2e8658fed7c6b24de38237d11d6f33e683becd299f019b192f9a462201d7),
        uint256(0x1a21a879a7b8d64da50d0138ae389c39e334dc56a5b25a700022ef406a769077)
        ]];
        uint256[2] memory proof_c = [uint256(0x133c448b093d7cb4a53839d68d07dc8c91ac8fb00046a149ffed8f4ac26c3d64),
        uint256(0x058e1675622c4bd5dde704613bb538863714e08169d51e3c5eb0a36f9ff539ea)
        ];
        
        uint256[6] memory pubSignals = [0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788,
            0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104,
            0x3021da71aa1435b4be7ced3ba1ac8058a0d2c796007e8b0b95483912a9e3728e,
            0x000000000000000000000000045ff23cf3413f6a355f0acc6ec6cb2721b95d99,
            0x0000000000000000000000000000000038aa871e9f0d65113cc34018b17050c3,
            0x00000000000000000000000000000000c00dea62a4eb345fdde7f5efd6f7c064];

        bool verified = verifier.verifyProof(proof_a, proof_b, proof_c, pubSignals);
        assertTrue(verified);
    }
}
