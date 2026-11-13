// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title AuditLogger
/// @notice Event-only immutable audit stream used by SXCPIntentHub.
contract AuditLogger {
    event IntentLogged(bytes32 indexed intentId, uint256 indexed sourceChainId, uint256 indexed destinationChainId);
    event AttestationLogged(
        bytes32 indexed attestationId,
        bytes32 indexed intentId,
        uint256 indexed sourceChainId,
        uint256 destinationChainId,
        uint256 epochId
    );
    event AttestationConsumedLogged(bytes32 indexed attestationId, address indexed consumer);

    function logIntent(bytes32 intentId, uint256 sourceChainId, uint256 destinationChainId) external {
        emit IntentLogged(intentId, sourceChainId, destinationChainId);
    }

    function logAttestation(
        bytes32 attestationId,
        bytes32 intentId,
        uint256 sourceChainId,
        uint256 destinationChainId,
        uint256 epochId
    ) external {
        emit AttestationLogged(attestationId, intentId, sourceChainId, destinationChainId, epochId);
    }

    function logAttestationConsumed(bytes32 attestationId, address consumer) external {
        emit AttestationConsumedLogged(attestationId, consumer);
    }
}
