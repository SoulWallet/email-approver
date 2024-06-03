// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Create2.sol";

contract EmailApproverFactory {
    address public immutable _APPROVERIMPL;

    event EmailApproverCreation(address indexed proxy);

    constructor(address _approverImpl) {
        _APPROVERIMPL = _approverImpl;
    }

    function proxyCode() external view returns (bytes memory) {
        return _proxyCode(_APPROVERIMPL);
    }
    /**
     * @notice  using solay ERC1967 https://github.com/Vectorized/solady/blob/5eff720c27746987dc95e5e2b720615d3d96f7ee/src/utils/LibClone.sol#L774C18-L774C18
     */

    function _proxyCode(address implementation) private pure returns (bytes memory deploymentData) {
        deploymentData = abi.encodePacked(
            hex"603d3d8160223d3973",
            implementation,
            hex"60095155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3"
        );
    }

    function createEmailApprover(bytes32 _senderCommitment, bytes32 _salt) external returns (address proxy) {
        address addr = getEmailApproverAddress(_senderCommitment, _salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return addr;
        }
        bytes memory _initializer = abi.encodeWithSignature("initialize(bytes32)", _senderCommitment);
        bytes memory deploymentData = _proxyCode(_APPROVERIMPL);
        bytes32 salt = _calcSalt(_initializer, _salt);
        assembly ("memory-safe") {
            proxy := create2(0x0, add(deploymentData, 0x20), mload(deploymentData), salt)
        }
        if (proxy == address(0)) {
            revert();
        }
        assembly ("memory-safe") {
            let succ := call(gas(), proxy, 0, add(_initializer, 0x20), mload(_initializer), 0, 0)
            if eq(succ, 0) { revert(0, 0) }
        }
        emit EmailApproverCreation(proxy);
    }

    function getEmailApproverAddress(bytes32 _senderCommitment, bytes32 _salt) public view returns (address proxy) {
        bytes memory _initializer = abi.encodeWithSignature("initialize(bytes32)", _senderCommitment);
        bytes memory deploymentData = _proxyCode(_APPROVERIMPL);
        bytes32 salt = _calcSalt(_initializer, _salt);
        proxy = Create2.computeAddress(salt, keccak256(deploymentData));
    }

    function _calcSalt(bytes memory _initializer, bytes32 _salt) private pure returns (bytes32 salt) {
        return keccak256(abi.encodePacked(keccak256(_initializer), _salt));
    }
}
