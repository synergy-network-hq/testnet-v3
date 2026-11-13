// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title SXCPVault (PQC-Secured)
/// @notice A chain-side vault used by the Synergy Cross-Chain Protocol (SXCP) to
/// lock and release assets. All attestation verification uses post-quantum
/// cryptographic commitments via the PQC SignatureVerifier — no classic ECDSA
/// signatures are used in the release pipeline.
///
/// Supports two modes:
/// 1) Atomic Swap Mode – hash-timelock based lock/claim/refund.
/// 2) Custody Mode – assets held until a PQC witness attestation quorum is verified.
contract SXCPVault {
    /// @notice Reference to the PQC SignatureVerifier for custody releases.
    address public signatureVerifier;
    address public witnessRegistry;
    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    event Deposit(address indexed depositor, uint256 amount, bytes32 hashLock, uint256 timeout);
    event Claim(address indexed claimer, uint256 amount);
    event Refund(address indexed refundee, uint256 amount);
    event CustodyReleased(bytes32 indexed depositId, address indexed recipient, uint256 amount, bytes32 pqcBundleCommitment);

    struct DepositRecord {
        uint256 amount;
        address depositor;
        bytes32 hashLock;
        uint256 timeout;
        bool claimed;
    }

    struct CustodyDeposit {
        uint256 amount;
        address depositor;
        address recipient;
        bytes32 intentId;
        uint256 epochId;
        bool released;
    }

    mapping(bytes32 => DepositRecord) public deposits;
    mapping(bytes32 => CustodyDeposit) public custodyDeposits;

    receive() external payable {}

    constructor(address signatureVerifier_, address witnessRegistry_) {
        require(signatureVerifier_ != address(0), "verifier=0");
        require(witnessRegistry_ != address(0), "registry=0");
        signatureVerifier = signatureVerifier_;
        witnessRegistry = witnessRegistry_;
        admin = msg.sender;
    }

    function updateVerifier(address signatureVerifier_) external onlyAdmin {
        require(signatureVerifier_ != address(0), "verifier=0");
        signatureVerifier = signatureVerifier_;
    }

    // --- Atomic Swap Mode (hash-timelock, no ECDSA) ---

    function depositHashTimelock(bytes32 hashLock, uint256 timeout) external payable returns (bytes32 depositId) {
        require(msg.value > 0, "Amount must be > 0");
        require(timeout > block.timestamp, "Timeout must be in the future");
        depositId = keccak256(abi.encodePacked(msg.sender, msg.value, hashLock, block.number));
        require(deposits[depositId].amount == 0, "Deposit already exists");
        deposits[depositId] = DepositRecord({
            amount: msg.value,
            depositor: msg.sender,
            hashLock: hashLock,
            timeout: timeout,
            claimed: false
        });
        emit Deposit(msg.sender, msg.value, hashLock, timeout);
    }

    function claim(bytes32 depositId, bytes32 preimage) external {
        DepositRecord storage record = deposits[depositId];
        require(record.amount > 0, "Invalid deposit");
        require(!record.claimed, "Already claimed");
        require(keccak256(abi.encodePacked(preimage)) == record.hashLock, "Invalid preimage");
        record.claimed = true;
        uint256 amount = record.amount;
        delete deposits[depositId];
        payable(msg.sender).transfer(amount);
        emit Claim(msg.sender, amount);
    }

    function refund(bytes32 depositId) external {
        DepositRecord storage record = deposits[depositId];
        require(record.amount > 0, "Invalid deposit");
        require(block.timestamp >= record.timeout, "Not expired");
        require(!record.claimed, "Already claimed");
        require(record.depositor == msg.sender, "Not depositor");
        uint256 amount = record.amount;
        delete deposits[depositId];
        payable(msg.sender).transfer(amount);
        emit Refund(msg.sender, amount);
    }

    // --- Custody Mode (PQC attestation-gated release) ---

    function depositCustody(
        bytes32 depositId,
        address recipient,
        bytes32 intentId,
        uint256 epochId
    ) external payable {
        require(msg.value > 0, "Amount must be > 0");
        CustodyDeposit storage cd = custodyDeposits[depositId];
        require(cd.amount == 0, "Deposit exists");
        cd.amount = msg.value;
        cd.depositor = msg.sender;
        cd.recipient = recipient;
        cd.intentId = intentId;
        cd.epochId = epochId;
        cd.released = false;
        emit Deposit(msg.sender, msg.value, bytes32(0), 0);
    }

    /// @notice Release a custody deposit by providing a verified PQC attestation bundle.
    /// The release is gated by the PQC SignatureVerifier — relayers must have signed
    /// with ML-DSA/FN-DSA/SLH-DSA and produced valid commitments.
    /// @param depositId The deposit identifier.
    /// @param digest The attestation digest signed by the relayer quorum.
    /// @param signers Sorted relayer addresses.
    /// @param pqcCommitments PQC signature commitments from each relayer.
    function releaseCustodyWithPQC(
        bytes32 depositId,
        bytes32 digest,
        address[] calldata signers,
        bytes[] calldata pqcCommitments
    ) external {
        CustodyDeposit storage cd = custodyDeposits[depositId];
        require(cd.amount > 0, "Invalid deposit");
        require(!cd.released, "Already released");

        // Verify PQC attestation bundle through the SignatureVerifier
        (bool success, bytes memory returnData) = signatureVerifier.call(
            abi.encodeWithSignature(
                "verify(bytes32,uint256,address[],bytes[])",
                digest,
                cd.epochId,
                signers,
                pqcCommitments
            )
        );
        require(success && abi.decode(returnData, (bool)), "PQC verification failed");

        cd.released = true;
        uint256 amount = cd.amount;
        address recipient = cd.recipient;

        // Compute bundle commitment for audit trail
        bytes32[] memory commitmentHashes = new bytes32[](pqcCommitments.length);
        for (uint256 i = 0; i < pqcCommitments.length; i++) {
            commitmentHashes[i] = bytes32(pqcCommitments[i]);
        }
        bytes32 bundleCommitment = keccak256(abi.encodePacked(digest, commitmentHashes));

        delete custodyDeposits[depositId];
        payable(recipient).transfer(amount);

        emit CustodyReleased(depositId, recipient, amount, bundleCommitment);
    }
}
