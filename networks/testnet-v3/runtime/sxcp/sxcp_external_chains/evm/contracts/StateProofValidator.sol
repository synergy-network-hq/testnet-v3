// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title StateProofValidator
/// @notice Minimal root allow-list validator for phase-1 testnet usage.
contract StateProofValidator is Ownable {
    mapping(bytes32 => bool) public approvedRoots;
    bool public requireApprovedRoots;

    event RootApprovalUpdated(bytes32 indexed root, bool approved);
    event RequireApprovedRootsUpdated(bool required);

    constructor(address admin, bool requireApprovedRoots_) Ownable(admin) {
        requireApprovedRoots = requireApprovedRoots_;
    }

    function setRequireApprovedRoots(bool required) external onlyOwner {
        requireApprovedRoots = required;
        emit RequireApprovedRootsUpdated(required);
    }

    function setApprovedRoot(bytes32 root, bool approved) external onlyOwner {
        approvedRoots[root] = approved;
        emit RootApprovalUpdated(root, approved);
    }

    function validate(bytes32 root) external view returns (bool) {
        if (!requireApprovedRoots) {
            return root != bytes32(0);
        }
        return approvedRoots[root];
    }
}
