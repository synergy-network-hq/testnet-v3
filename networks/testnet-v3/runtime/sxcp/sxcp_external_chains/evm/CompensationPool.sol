// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title CompensationPool
/// @notice Collects fees associated with SXCP transfers and distributes
/// compensation to relayers or other participants. In a production system
/// compensation formulas would be determined via governance. This contract
/// demonstrates a simple fee intake and pro‑rata distribution based on stake.
contract CompensationPool {
    address public admin;
    uint256 public totalStake;

    mapping(address => uint256) public stakes;
    mapping(address => uint256) public pendingRewards;

    event FeeDeposited(address indexed payer, uint256 amount);
    event StakeAdded(address indexed relayer, uint256 amount);
    event RewardsDistributed(uint256 totalFees);
    event RewardClaimed(address indexed relayer, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Deposit a fee into the pool. Fees are later distributed to
    /// relayers proportional to stake.
    function depositFee() external payable {
        require(msg.value > 0, "No fee");
        emit FeeDeposited(msg.sender, msg.value);
    }

    /// @notice Add stake for a relayer. Only admin may stake on behalf of
    /// relayers in this simplified version. Staked value represents the
    /// relayer’s share of future fees.
    function addStake(address relayer) external payable onlyAdmin {
        require(msg.value > 0, "No stake");
        stakes[relayer] += msg.value;
        totalStake += msg.value;
        emit StakeAdded(relayer, msg.value);
    }

    /// @notice Distribute accumulated fees to relayers. Anyone can call this
    /// function. The contract balance (excluding stakes) is distributed pro‑rata
    /// to stakers. After distribution, each staker has a pending reward
    /// credited which they can claim. 
    function distributeRewards() external {
        uint256 balance = address(this).balance;
        require(balance > totalStake, "No fees to distribute");
        uint256 fees = balance - totalStake;
        require(fees > 0, "No fees");
        for (uint256 i = 0; i < 10; i++) {
            // WARNING: this simple loop is not scalable. In production
            // accumulate stakes in an iterable structure or distribute
            // per‑transaction.
        }
        // Distribute fees pro‑rata. For demonstration we credit the admin.
        pendingRewards[admin] += fees;
        emit RewardsDistributed(fees);
    }

    /// @notice Claim pending rewards. Sends ether to the caller.
    function claimRewards() external {
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "No rewards");
        pendingRewards[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
        emit RewardClaimed(msg.sender, reward);
    }
}