// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title WitnessRegistry (PQC-Enhanced)
/// @notice Tracks active SXCP witnesses and epoch-specific signer sets with
/// post-quantum cryptographic key commitments. Each relayer registers a PQC
/// public key commitment (keccak256 of their ML-DSA/FN-DSA/SLH-DSA public key)
/// alongside their Ethereum address. The SignatureVerifier uses this registry
/// to validate PQC attestation bundles.
contract WitnessRegistry is Ownable {
    /// @notice PQC algorithm identifiers matching Aegis-PQVM.
    uint8 public constant ALGO_MLDSA = 1;
    uint8 public constant ALGO_FNDSA = 2;
    uint8 public constant ALGO_SLHDSA = 3;

    struct RelayerInfo {
        bool active;
        uint256 reputation;
        uint256 activatedAt;
        bytes32 pqcKeyCommitment;     // keccak256(pqcPublicKeyBytes)
        uint8 pqcAlgorithmId;         // Which PQC algorithm this relayer uses
        uint256 pqcKeyRegisteredAt;   // Block number when PQC key was registered
    }

    mapping(address => RelayerInfo) public relayers;
    mapping(uint256 => mapping(address => bool)) private epochRelayers;
    mapping(uint256 => uint256) public epochThreshold;
    mapping(uint256 => uint256) public epochRelayerCount;

    uint256 public currentEpoch;

    event RelayerStatusUpdated(address indexed relayer, bool active);
    event ReputationUpdated(address indexed relayer, int256 delta, uint256 newScore);
    event EpochRotated(uint256 indexed epochId, uint256 threshold, address[] relayers);
    event PQCKeyRegistered(
        address indexed relayer,
        bytes32 pqcKeyCommitment,
        uint8 pqcAlgorithmId
    );

    constructor(address admin, uint256 initialThreshold, address[] memory initialRelayers) Ownable(admin) {
        _setEpoch(1, initialThreshold, initialRelayers);
        currentEpoch = 1;
    }

    /// @notice Register or update a relayer's PQC public key commitment.
    /// @param relayer The relayer address.
    /// @param pqcKeyCommitment keccak256 hash of the relayer's PQC public key bytes.
    /// @param pqcAlgorithmId The PQC algorithm (1=ML-DSA, 2=FN-DSA, 3=SLH-DSA).
    function registerPQCKey(
        address relayer,
        bytes32 pqcKeyCommitment,
        uint8 pqcAlgorithmId
    ) external onlyOwner {
        require(relayer != address(0), "relayer=0");
        require(pqcKeyCommitment != bytes32(0), "commitment=0");
        require(
            pqcAlgorithmId == ALGO_MLDSA ||
            pqcAlgorithmId == ALGO_FNDSA ||
            pqcAlgorithmId == ALGO_SLHDSA,
            "unsupported algorithm"
        );

        RelayerInfo storage info = relayers[relayer];
        info.pqcKeyCommitment = pqcKeyCommitment;
        info.pqcAlgorithmId = pqcAlgorithmId;
        info.pqcKeyRegisteredAt = block.number;

        emit PQCKeyRegistered(relayer, pqcKeyCommitment, pqcAlgorithmId);
    }

    /// @notice Check if a relayer has a registered PQC key.
    function hasPQCKey(address relayer) external view returns (bool) {
        return relayers[relayer].pqcKeyCommitment != bytes32(0);
    }

    /// @notice Get a relayer's PQC key commitment and algorithm.
    function getPQCKey(address relayer) external view returns (bytes32 commitment, uint8 algorithmId) {
        RelayerInfo storage info = relayers[relayer];
        return (info.pqcKeyCommitment, info.pqcAlgorithmId);
    }

    function setRelayerStatus(address relayer, bool active) external onlyOwner {
        require(relayer != address(0), "relayer=0");
        RelayerInfo storage info = relayers[relayer];
        if (active && !info.active) {
            info.active = true;
            info.activatedAt = block.number;
        } else if (!active && info.active) {
            info.active = false;
        }
        emit RelayerStatusUpdated(relayer, active);
    }

    function updateReputation(address relayer, int256 delta) external onlyOwner {
        RelayerInfo storage info = relayers[relayer];
        require(info.active, "inactive");
        if (delta < 0) {
            uint256 absDelta = uint256(-delta);
            if (info.reputation > absDelta) {
                info.reputation -= absDelta;
            } else {
                info.reputation = 0;
            }
        } else {
            info.reputation += uint256(delta);
        }
        emit ReputationUpdated(relayer, delta, info.reputation);
    }

    function rotateEpoch(uint256 newThreshold, address[] calldata relayerSet) external onlyOwner returns (uint256) {
        uint256 nextEpoch = currentEpoch + 1;
        _setEpoch(nextEpoch, newThreshold, relayerSet);
        currentEpoch = nextEpoch;
        return nextEpoch;
    }

    function isActiveRelayer(address relayer, uint256 epochId) external view returns (bool) {
        if (epochId == 0 || epochId == currentEpoch) {
            return relayers[relayer].active;
        }
        if (epochThreshold[epochId] == 0) {
            return false;
        }
        return epochRelayers[epochId][relayer];
    }

    function getThreshold(uint256 epochId) external view returns (uint256) {
        if (epochId == 0 || epochId == currentEpoch) {
            return epochThreshold[currentEpoch];
        }
        return epochThreshold[epochId];
    }

    function _setEpoch(uint256 epochId, uint256 threshold, address[] memory relayerSet) internal {
        require(threshold > 0, "threshold=0");
        require(relayerSet.length >= threshold, "threshold>n");

        for (uint256 i = 0; i < relayerSet.length; i++) {
            address relayer = relayerSet[i];
            require(relayer != address(0), "relayer=0");
            require(!epochRelayers[epochId][relayer], "duplicate relayer");
            epochRelayers[epochId][relayer] = true;
            relayers[relayer].active = true;
            if (relayers[relayer].activatedAt == 0) {
                relayers[relayer].activatedAt = block.number;
            }
        }

        epochThreshold[epochId] = threshold;
        epochRelayerCount[epochId] = relayerSet.length;
        emit EpochRotated(epochId, threshold, relayerSet);
    }
}
