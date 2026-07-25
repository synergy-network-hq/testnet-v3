// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title GovernanceModule
/// @notice Shared on-chain control plane for SXCP modules on one chain.
contract GovernanceModule is Ownable2Step, Pausable {
    mapping(bytes32 => uint256) private uintParams;
    mapping(bytes32 => bool) private hasUintParam;

    event UintParamUpdated(bytes32 indexed key, uint256 value);

    constructor(address admin) Ownable(admin) {}

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function setUintParam(bytes32 key, uint256 value) external onlyOwner {
        uintParams[key] = value;
        hasUintParam[key] = true;
        emit UintParamUpdated(key, value);
    }

    function getUintParam(bytes32 key, uint256 defaultValue) external view returns (uint256) {
        if (!hasUintParam[key]) {
            return defaultValue;
        }
        return uintParams[key];
    }
}
