// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

interface IAuditLogger {
    function logIntent(bytes32 intentId, uint256 sourceChainId, uint256 destinationChainId) external;
    function logAttestation(
        bytes32 attestationId,
        bytes32 intentId,
        uint256 sourceChainId,
        uint256 destinationChainId,
        uint256 epochId
    ) external;
    function logAttestationConsumed(bytes32 attestationId, address consumer) external;
}

interface ISignatureVerifier {
    /// @notice PQC-compatible verification interface.
    /// @param digest The attestation digest signed off-chain with PQC algorithms.
    /// @param epochId The epoch for signer validation.
    /// @param signers Sorted relayer addresses that produced PQC signatures.
    /// @param pqcCommitments PQC signature commitments (keccak256 of algo+pubkey+sig+digest).
    function verify(
        bytes32 digest,
        uint256 epochId,
        address[] calldata signers,
        bytes[] calldata pqcCommitments
    ) external returns (bool);
}

interface IFinalityChecker {
    function isFinalized(
        uint256 sourceChainId,
        uint256 sourceBlockNumber,
        uint256 observedSourceHead
    ) external view returns (bool);
}

interface IStateProofValidator {
    function validate(bytes32 root) external view returns (bool);
}

/// @title SXCPIntentHub (PQC-Secured)
/// @notice V2-aligned SXCP coordination contract with post-quantum cryptographic
/// attestation verification. This contract does not custody assets. It records
/// intent commitments and verifies PQC attestation bundles that destination-side
/// applications can consume.
///
/// All signature verification uses post-quantum algorithms (ML-DSA, FN-DSA,
/// SLH-DSA) via the Aegis-PQVM commitment scheme. No classic ECDSA signatures
/// are used in the attestation pipeline.
contract SXCPIntentHub is Ownable, Pausable {
    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "SXCP_PQC_ATTESTATION_V2(uint256 sourceChainId,uint256 destinationChainId,bytes32 intentId,bytes32 scopeDigest,bytes32 sourceCommitmentRef,uint64 sourceBlockNumber,uint64 sourceLogIndex,uint256 expiry,uint256 epochId,bytes32 stateProofRoot,uint8 pqcAlgorithmId)"
    );

    /// @notice PQC algorithm identifiers matching Aegis-PQVM.
    uint8 public constant PQC_ALGO_MLDSA = 1;
    uint8 public constant PQC_ALGO_FNDSA = 2;
    uint8 public constant PQC_ALGO_SLHDSA = 3;

    struct IntentCommitment {
        address sender;
        uint256 sourceChainId;
        uint256 destinationChainId;
        bytes32 scopeDigest;
        uint256 expiry;
        uint256 nonce;
        uint64 committedAtBlock;
        bool exists;
    }

    struct RemoteEndpoint {
        address intentHub;
        address witnessRegistry;
        bool enabled;
    }

    struct VerifiedAttestationRecord {
        bytes32 intentId;
        uint256 sourceChainId;
        uint256 destinationChainId;
        uint256 epochId;
        uint8 pqcAlgorithmId;
        bytes32 bundleCommitment;
        uint256 verifiedAt;
        bool consumed;
    }

    ISignatureVerifier public signatureVerifier;
    IFinalityChecker public finalityChecker;
    IStateProofValidator public stateProofValidator;
    IAuditLogger public auditLogger;

    mapping(bytes32 => IntentCommitment) public intents;
    mapping(uint256 => RemoteEndpoint) public remoteEndpoints;
    mapping(bytes32 => bool) public verifiedAttestations;
    mapping(bytes32 => bool) public consumedAttestations;
    mapping(bytes32 => VerifiedAttestationRecord) public attestationRecords;

    event IntentCommitted(
        bytes32 indexed intentId,
        address indexed sender,
        uint256 indexed destinationChainId,
        bytes32 scopeDigest,
        uint256 expiry,
        uint256 nonce
    );
    event PQCAttestationVerified(
        bytes32 indexed attestationId,
        bytes32 indexed intentId,
        uint256 indexed sourceChainId,
        uint256 destinationChainId,
        uint256 epochId,
        uint8 pqcAlgorithmId,
        bytes32 bundleCommitment
    );
    event AttestationConsumed(bytes32 indexed attestationId, address indexed consumer);
    event RemoteEndpointSet(
        uint256 indexed chainId,
        address indexed remoteIntentHub,
        address indexed remoteWitnessRegistry,
        bool enabled
    );
    event VerifierModulesUpdated(
        address signatureVerifier,
        address finalityChecker,
        address stateProofValidator,
        address auditLogger
    );

    constructor(
        address admin,
        address signatureVerifier_,
        address finalityChecker_,
        address stateProofValidator_,
        address auditLogger_
    ) Ownable(admin) {
        _setVerifierModules(signatureVerifier_, finalityChecker_, stateProofValidator_, auditLogger_);
    }

    function setRemoteEndpoint(
        uint256 chainId,
        address remoteIntentHub,
        address remoteWitnessRegistry,
        bool enabled
    ) external onlyOwner {
        require(chainId > 0, "chainId=0");
        require(remoteIntentHub != address(0), "intentHub=0");
        require(remoteWitnessRegistry != address(0), "witnessRegistry=0");
        remoteEndpoints[chainId] = RemoteEndpoint({
            intentHub: remoteIntentHub,
            witnessRegistry: remoteWitnessRegistry,
            enabled: enabled
        });
        emit RemoteEndpointSet(chainId, remoteIntentHub, remoteWitnessRegistry, enabled);
    }

    function setVerifierModules(
        address signatureVerifier_,
        address finalityChecker_,
        address stateProofValidator_,
        address auditLogger_
    ) external onlyOwner {
        _setVerifierModules(signatureVerifier_, finalityChecker_, stateProofValidator_, auditLogger_);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function publishIntent(
        bytes32 intentId,
        uint256 destinationChainId,
        bytes32 scopeDigest,
        uint256 expiry,
        uint256 nonce
    ) external whenNotPaused {
        require(intentId != bytes32(0), "intentId=0");
        require(scopeDigest != bytes32(0), "scopeDigest=0");
        require(expiry > block.timestamp, "intent expired");
        require(destinationChainId != block.chainid, "destination=source");
        require(!intents[intentId].exists, "intent exists");

        intents[intentId] = IntentCommitment({
            sender: msg.sender,
            sourceChainId: block.chainid,
            destinationChainId: destinationChainId,
            scopeDigest: scopeDigest,
            expiry: expiry,
            nonce: nonce,
            committedAtBlock: uint64(block.number),
            exists: true
        });

        emit IntentCommitted(intentId, msg.sender, destinationChainId, scopeDigest, expiry, nonce);
        if (address(auditLogger) != address(0)) {
            auditLogger.logIntent(intentId, block.chainid, destinationChainId);
        }
    }

    /// @notice Compute the attestation digest including the PQC algorithm identifier.
    function computeAttestationDigest(
        uint256 sourceChainId,
        uint256 destinationChainId,
        bytes32 intentId,
        bytes32 scopeDigest,
        bytes32 sourceCommitmentRef,
        uint64 sourceBlockNumber,
        uint64 sourceLogIndex,
        uint256 expiry,
        uint256 epochId,
        bytes32 stateProofRoot,
        uint8 pqcAlgorithmId
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ATTESTATION_TYPEHASH,
                    sourceChainId,
                    destinationChainId,
                    intentId,
                    scopeDigest,
                    sourceCommitmentRef,
                    sourceBlockNumber,
                    sourceLogIndex,
                    expiry,
                    epochId,
                    stateProofRoot,
                    pqcAlgorithmId
                )
            );
    }

    /// @notice Verify a PQC attestation bundle from cross-chain relayers.
    /// @param pqcAlgorithmId The PQC algorithm used (1=ML-DSA, 2=FN-DSA, 3=SLH-DSA).
    /// @param signers Sorted relayer addresses.
    /// @param pqcCommitments PQC signature commitments (one per signer).
    function verifyAttestationBundle(
        uint256 sourceChainId,
        bytes32 intentId,
        bytes32 scopeDigest,
        bytes32 sourceCommitmentRef,
        uint64 sourceBlockNumber,
        uint64 sourceLogIndex,
        uint256 observedSourceHead,
        uint256 expiry,
        uint256 epochId,
        bytes32 stateProofRoot,
        uint8 pqcAlgorithmId,
        address[] calldata signers,
        bytes[] calldata pqcCommitments
    ) external whenNotPaused returns (bytes32 attestationId) {
        require(sourceChainId != block.chainid, "source=destination");
        require(intentId != bytes32(0), "intentId=0");
        require(scopeDigest != bytes32(0), "scopeDigest=0");
        require(sourceCommitmentRef != bytes32(0), "commitRef=0");
        require(expiry >= block.timestamp, "attestation expired");
        require(
            pqcAlgorithmId == PQC_ALGO_MLDSA ||
            pqcAlgorithmId == PQC_ALGO_FNDSA ||
            pqcAlgorithmId == PQC_ALGO_SLHDSA,
            "unsupported PQC algorithm"
        );

        RemoteEndpoint memory endpoint = remoteEndpoints[sourceChainId];
        require(endpoint.enabled, "source chain disabled");

        require(
            finalityChecker.isFinalized(sourceChainId, sourceBlockNumber, observedSourceHead),
            "source not final"
        );
        require(stateProofValidator.validate(stateProofRoot), "proof root invalid");

        bytes32 digest = computeAttestationDigest(
            sourceChainId,
            block.chainid,
            intentId,
            scopeDigest,
            sourceCommitmentRef,
            sourceBlockNumber,
            sourceLogIndex,
            expiry,
            epochId,
            stateProofRoot,
            pqcAlgorithmId
        );

        require(
            signatureVerifier.verify(digest, epochId, signers, pqcCommitments),
            "PQC bundle invalid"
        );

        attestationId = keccak256(abi.encodePacked(digest, signers, pqcAlgorithmId));
        require(!verifiedAttestations[attestationId], "already verified");
        verifiedAttestations[attestationId] = true;

        // Compute bundle commitment for the record
        bytes32 bundleCommitment;
        {
            bytes32[] memory commitmentHashes = new bytes32[](pqcCommitments.length);
            for (uint256 i = 0; i < pqcCommitments.length; i++) {
                commitmentHashes[i] = bytes32(pqcCommitments[i]);
            }
            bundleCommitment = keccak256(abi.encodePacked(digest, commitmentHashes));
        }

        attestationRecords[attestationId] = VerifiedAttestationRecord({
            intentId: intentId,
            sourceChainId: sourceChainId,
            destinationChainId: block.chainid,
            epochId: epochId,
            pqcAlgorithmId: pqcAlgorithmId,
            bundleCommitment: bundleCommitment,
            verifiedAt: block.timestamp,
            consumed: false
        });

        emit PQCAttestationVerified(
            attestationId,
            intentId,
            sourceChainId,
            block.chainid,
            epochId,
            pqcAlgorithmId,
            bundleCommitment
        );
        if (address(auditLogger) != address(0)) {
            auditLogger.logAttestation(attestationId, intentId, sourceChainId, block.chainid, epochId);
        }
    }

    function consumeVerifiedAttestation(bytes32 attestationId) external whenNotPaused {
        require(verifiedAttestations[attestationId], "not verified");
        require(!consumedAttestations[attestationId], "already consumed");
        consumedAttestations[attestationId] = true;

        if (attestationRecords[attestationId].verifiedAt > 0) {
            attestationRecords[attestationId].consumed = true;
        }

        emit AttestationConsumed(attestationId, msg.sender);
        if (address(auditLogger) != address(0)) {
            auditLogger.logAttestationConsumed(attestationId, msg.sender);
        }
    }

    function isAttestationConsumable(bytes32 attestationId) external view returns (bool) {
        return verifiedAttestations[attestationId] && !consumedAttestations[attestationId];
    }

    function getAttestationRecord(bytes32 attestationId) external view returns (VerifiedAttestationRecord memory) {
        return attestationRecords[attestationId];
    }

    function _setVerifierModules(
        address signatureVerifier_,
        address finalityChecker_,
        address stateProofValidator_,
        address auditLogger_
    ) internal {
        require(signatureVerifier_ != address(0), "signatureVerifier=0");
        require(finalityChecker_ != address(0), "finalityChecker=0");
        require(stateProofValidator_ != address(0), "stateProofValidator=0");
        signatureVerifier = ISignatureVerifier(signatureVerifier_);
        finalityChecker = IFinalityChecker(finalityChecker_);
        stateProofValidator = IStateProofValidator(stateProofValidator_);
        auditLogger = IAuditLogger(auditLogger_);
        emit VerifierModulesUpdated(signatureVerifier_, finalityChecker_, stateProofValidator_, auditLogger_);
    }
}
