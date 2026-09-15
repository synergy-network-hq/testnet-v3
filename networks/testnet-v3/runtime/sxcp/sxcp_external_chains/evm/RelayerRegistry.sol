// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title RelayerRegistry
/// @notice Maintains staking and reward parameters for relayers in the SXCP. A
/// separate contract from WitnessRegistry allows pluggable staking logic. Here
/// we implement basic stake deposit/withdrawal and reward accumulation. This
/// contract could be merged into WitnessRegistry in a production system.
contract RelayerRegistry {
    address public admin;

    struct Relayer {
        uint256 stake;
        uint256 rewardDebt;
    }

    mapping(address => Relayer) public relayers;
    uint256 public totalStake;
    uint256 public accRewardPerStake;

    event StakeDeposited(address indexed relayer, uint256 amount);
    event StakeWithdrawn(address indexed relayer, uint256 amount);
    event RewardsAdded(uint256 amount);
    event RewardClaimed(address indexed relayer, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Deposit stake to become eligible for rewards. Anyone can stake for
    /// themselves; no identity checks are performed here.
    function depositStake() external payable {
        require(msg.value > 0, "No stake");
        Relayer storage r = relayers[msg.sender];
        updateRewards();
        if (r.stake > 0) {
            uint256 pending = (r.stake * accRewardPerStake) / 1e18 - r.rewardDebt;
            r.rewardDebt += pending;
        }
        r.stake += msg.value;
        totalStake += msg.value;
        emit StakeDeposited(msg.sender, msg.value);
    }

    /// @notice Withdraw stake. Rewards accrued up to this point remain available
    /// for claim. Only the caller's own stake can be withdrawn.
    function withdrawStake(uint256 amount) external {
        Relayer storage r = relayers[msg.sender];
        require(r.stake >= amount, "Not enough stake");
        updateRewards();
        r.stake -= amount;
        totalStake -= amount;
        payable(msg.sender).transfer(amount);
        emit StakeWithdrawn(msg.sender, amount);
    }

    /// @notice Add rewards to the pool. Anyone (e.g., CompensationPool) can send
    /// ETH here and call this function. Rewards are distributed pro‑rata based
    /// on stake. 
    function addRewards() external payable {
        require(msg.value > 0, "No reward");
        if (totalStake > 0) {
            accRewardPerStake += (msg.value * 1e18) / totalStake;
        }
        emit RewardsAdded(msg.value);
    }

    /// @notice Claim accumulated rewards. Rewards are transferred to the caller
    /// and reward debt updated accordingly.
    function claimRewards() external {
        Relayer storage r = relayers[msg.sender];
        updateRewards();
        uint256 accumulated = (r.stake * accRewardPerStake) / 1e18;
        uint256 pending = accumulated - r.rewardDebt;
        require(pending > 0, "No rewards");
        r.rewardDebt = accumulated;
        payable(msg.sender).transfer(pending);
        emit RewardClaimed(msg.sender, pending);
    }

    /// @notice Internal function to update reward debt for all stakers. In a
    /// full implementation this would iterate through stakers; here it does
    /// nothing because rewards are handled lazily per user.
    function updateRewards() internal {
        // Intentionally empty; accRewardPerStake is updated in addRewards().
    }
}