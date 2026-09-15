// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title FinalityChecker
/// @notice Holds per-chain finality confirmation policies for SXCP attestations.
contract FinalityChecker is Ownable {
    mapping(uint256 => uint256) public confirmationsByChain;

    event ConfirmationsUpdated(uint256 indexed chainId, uint256 confirmations);

    constructor(address admin, uint256[] memory chainIds, uint256[] memory confirmations) Ownable(admin) {
        require(chainIds.length == confirmations.length, "length mismatch");
        for (uint256 i = 0; i < chainIds.length; i++) {
            _setConfirmations(chainIds[i], confirmations[i]);
        }
    }

    function setConfirmations(uint256 chainId, uint256 confirmations) external onlyOwner {
        _setConfirmations(chainId, confirmations);
    }

    /// @notice Checks finality for a source chain.
    /// For foreign chains, `observedSourceHead` is a relayer-observed source
    /// head included in the attestation package.
    function isFinalized(
        uint256 sourceChainId,
        uint256 sourceBlockNumber,
        uint256 observedSourceHead
    ) external view returns (bool) {
        uint256 requiredConfirmations = confirmationsByChain[sourceChainId];
        require(requiredConfirmations > 0, "chain unconfigured");

        if (sourceChainId == block.chainid) {
            return block.number >= sourceBlockNumber + requiredConfirmations;
        }

        return observedSourceHead >= sourceBlockNumber + requiredConfirmations;
    }

    function _setConfirmations(uint256 chainId, uint256 confirmations) internal {
        require(chainId > 0, "chainId=0");
        require(confirmations > 0, "confirmations=0");
        confirmationsByChain[chainId] = confirmations;
        emit ConfirmationsUpdated(chainId, confirmations);
    }
}
