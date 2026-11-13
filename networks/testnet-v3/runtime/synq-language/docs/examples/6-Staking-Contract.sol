// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Generated from SynQ source
// WARNING: Solidity compatibility preview only; not production deployable.
// This file is auto-generated - do not edit manually

// PQC library imports (to be implemented)
// import "@synq/pqc/MLDSA.sol";
// import "@synq/pqc/FNDSA.sol";
// import "@synq/pqc/MLKEM.sol";
// import "@synq/pqc/SLH-DSA.sol";

contract PQCStaking {
address public stakingToken;
address public rewardToken;
uint256 public rewardRate;
uint256 public totalStaked;
uint256 public lastUpdateBlock;
uint256 public rewardPerTokenStored;
mapping(address => Staker) public stakers;
address[] public stakerList;
uint256 public minLockPeriod;
uint256 public maxLockPeriod;
mapping(address => uint256) public lockUntil;
bytes memory public withdrawalKey;
bool public withdrawalsEnabled;

constructor(address _stakingToken, address _rewardToken, uint256 _rewardRate, uint256 _minLockPeriod, uint256 _maxLockPeriod, bytes memory _withdrawalKey) {
stakingToken = _stakingToken;
rewardToken = _rewardToken;
rewardRate = _rewardRate;
minLockPeriod = _minLockPeriod;
maxLockPeriod = _maxLockPeriod;
withdrawalKey = _withdrawalKey;
totalStaked = 0;
lastUpdateBlock = block.number;
rewardPerTokenStored = 0;
withdrawalsEnabled = true;
}

event Staked((address staker, uint256 amount, uint256 lockUntil));
event Unstaked((address staker, uint256 amount));
event RewardClaimed((address staker, uint256 amount));
event RewardRateUpdated((uint256 oldRate, uint256 newRate));
event WithdrawalKeyUpdated((bytes memory newKey));

function updateReward() internal {
if (totalStaked == 0) {
lastUpdateBlock = block.number;
return;
}
uint256 blocksSinceUpdate = block.number - lastUpdateBlock;
uint256 newRewards = (blocksSinceUpdate * rewardRate * 1e18) / totalStaked;
rewardPerTokenStored = rewardPerTokenStored + newRewards;
lastUpdateBlock = block.number;
}

function rewardPerToken() external returns (uint256) public {
if (totalStaked == 0) {
return rewardPerTokenStored;
}
uint256 blocksSinceUpdate = block.number - lastUpdateBlock;
uint256 newRewards = (blocksSinceUpdate * rewardRate * 1e18) / totalStaked;
return rewardPerTokenStored + newRewards;
}

function earned(address staker) external returns (uint256) public {
Staker s = stakers[staker];
if (s.stakedAmount == 0) {
return 0;
}
uint256 currentRewardPerToken = rewardPerToken();
uint256 reward = (s.stakedAmount * (currentRewardPerToken - s.rewardDebt)) / 1e18;
return reward;
}

function stake(uint256 amount, uint256 lockPeriod) public {
require(amount > 0, "Amount must be positive");
require(lockPeriod >= minLockPeriod, "Lock period too short");
require(lockPeriod <= maxLockPeriod, "Lock period too long");
updateReward();
Staker s = stakers[msg.sender];
if (s.stakedAmount > 0) {
uint256 pendingReward = earned(msg.sender);
if (pendingReward > 0) {
s.totalEarned = s.totalEarned + pendingReward;
}
}
if (!s.active) {
s.active = true;
stakerList.push(msg.sender);
}
s.stakedAmount = s.stakedAmount + amount;
s.rewardDebt = (s.stakedAmount * rewardPerTokenStored) / 1e18;
s.lastStakeBlock = block.number;
uint256 newLockUntil = block.number + lockPeriod;
if (lockUntil[msg.sender] < newLockUntil) {
lockUntil[msg.sender] = newLockUntil;
}
totalStaked = totalStaked + amount;
emit Staked((msg.sender, amount, lockUntil[msg.sender]));
}

function unstake(uint256 amount) public {
require(amount > 0, "Amount must be positive");
Staker s = stakers[msg.sender];
require(s.stakedAmount >= amount, "Insufficient staked amount");
require(block.number >= lockUntil[msg.sender], "Stake still locked");
updateReward();
uint256 pendingReward = earned(msg.sender);
if (pendingReward > 0) {
s.totalEarned = s.totalEarned + pendingReward;
emit RewardClaimed((msg.sender, pendingReward));
}
s.stakedAmount = s.stakedAmount - amount;
s.rewardDebt = (s.stakedAmount * rewardPerTokenStored) / 1e18;
totalStaked = totalStaked - amount;
if (s.stakedAmount == 0) {
s.active = false;
}
emit Unstaked((msg.sender, amount));
}

function claimRewards() public {
Staker s = stakers[msg.sender];
require(s.stakedAmount > 0, "No staked amount");
updateReward();
uint256 pendingReward = earned(msg.sender);
require(pendingReward > 0, "No rewards to claim");
s.totalEarned = s.totalEarned + pendingReward;
s.rewardDebt = (s.stakedAmount * rewardPerTokenStored) / 1e18;
emit RewardClaimed((msg.sender, pendingReward));
}

// @gas_cost
function emergencyWithdraw(uint256 amount, bytes messageToSign, bytes memory signature) public // @gas_cost() {
require(!withdrawalsEnabled, "Normal withdrawals enabled");
Staker s = stakers[msg.sender];
require(s.stakedAmount >= amount, "Insufficient staked amount");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(withdrawalKey, messageToSign, signature);
require(isValid, "Invalid withdrawal signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
s.stakedAmount = s.stakedAmount - amount;
totalStaked = totalStaked - amount;
if (s.stakedAmount == 0) {
s.active = false;
}
emit Unstaked((msg.sender, amount));
}

// @gas_cost
function updateRewardRate(uint256 newRate, bytes messageToSign, bytes memory signature) public // @gas_cost() {
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(withdrawalKey, messageToSign, signature);
require(isValid, "Invalid signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
updateReward();
uint256 oldRate = rewardRate;
rewardRate = newRate;
emit RewardRateUpdated((oldRate, newRate));
}

// @gas_cost
function updateWithdrawalKey(bytes memory newKey, bytes messageToSign, bytes memory signature) public // @gas_cost() {
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(withdrawalKey, messageToSign, signature);
require(isValid, "Invalid signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
withdrawalKey = newKey;
emit WithdrawalKeyUpdated((newKey));
}

// @gas_cost
function setWithdrawalsEnabled(bool enabled, bytes messageToSign, bytes memory signature) public // @gas_cost() {
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(withdrawalKey, messageToSign, signature);
require(isValid, "Invalid signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
withdrawalsEnabled = enabled;
}

function getStakerInfo(address staker) external returns (Tuple) public {
Staker s = stakers[staker];
return         (
                    s.stakedAmount,
                    earned(staker),
                    s.totalEarned,
                    s.lastStakeBlock,
                    lockUntil[staker],
                    s.active
                );
}

function getStakerCount() external returns (uint256) public {
return stakerList.length;
}

function isLocked(address staker) external returns (bool) public {
return block.number < lockUntil[staker];
}

function timeUntilUnlock(address staker) external returns (uint256) public {
if (block.number >= lockUntil[staker]) {
return 0;
}
return lockUntil[staker] - block.number;
}

function compound() public {
Staker s = stakers[msg.sender];
require(s.stakedAmount > 0, "No staked amount");
updateReward();
uint256 pendingReward = earned(msg.sender);
require(pendingReward > 0, "No rewards to compound");
s.totalEarned = s.totalEarned + pendingReward;
s.rewardDebt = ((s.stakedAmount + pendingReward) * rewardPerTokenStored) / 1e18;
s.stakedAmount = s.stakedAmount + pendingReward;
totalStaked = totalStaked + pendingReward;
emit Staked((msg.sender, pendingReward, lockUntil[msg.sender]));
}

}

