// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Groth16Verifier} from "../src/Verifier.sol";

contract CounterTest is Test {
    Groth16Verifier public verifier;

    function setUp() public {
        verifier = new Groth16Verifier();
    }

    function test_verifier() public view {
        uint[2] memory _pA = [
            0x2817e92787efa427962b8f1fc163a8d1967b61de29ed2f8a7c33077660cd4de3,
            0x122ffc6c6e086a151e936c51e4eadc85b9765d79a787952979f1561d491b7b7d
        ];
        uint[2][2] memory _pB = [
            [
                0x1882a24d6b66e78df91c6f177c1f5d401f0394f184df61da935bb5ad3c571659,
                0x1810d00832bb68c589372df7b5b282e9e155b8c7fed793bbf8123db0b6c7394a
            ],
            [
                0x06c66aa32c38c231cb7ec9d9db7b6c68e73a4ba238bcdc20e2ee516c3701222c,
                0x1a64fb1c0cd94c62098a4b0d8a06999dd97f250f3f160f9e2b5900a748974b02
            ]
        ];
        uint[2] memory _pC = [
            0x1b71eea0511cf779e882680229813f977ec694d3c2e81780c2aa34d967f0bc7d,
            0x2ce634b47ed9cc14d861cf6f2e9e15f2b4e960f59f1e7fff01cfb811be49cff0
        ];
        uint[6] memory _pubSignals = [
            0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788,
            0x2ace34e59a0b27c7142b61cef52c7770bb8a1414cf19145e69661826c127e104,
            0x3021da71aa1435b4be7ced3ba1ac8058a0d2c796007e8b0b95483912a9e3728e,
            0x000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a,
            0x0000000000000000000000000000000038aa871e9f0d65113cc34018b17050c3,
            0x00000000000000000000000000000000c00dea62a4eb345fdde7f5efd6f7c064
        ];
        bool ret = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        assert(ret);
    }
}
