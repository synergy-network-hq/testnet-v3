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

contract PQCToken {
string public name;
string public symbol;
uint8 public decimals;
uint256 public totalSupply;
address public owner;
mapping(address => uint256) public balanceOf;
mapping(address => mapping(address => uint256)) public allowance;
bytes memory public governanceKey;
bool public paused;

constructor(string _name, string _symbol, uint8 _decimals, uint256 _initialSupply, bytes memory _governanceKey) {
name = _name;
symbol = _symbol;
decimals = _decimals;
owner = msg.sender;
governanceKey = _governanceKey;
totalSupply = _initialSupply;
balanceOf[msg.sender] = _initialSupply;
emit Transfer((Address(0), msg.sender, _initialSupply));
}

event Transfer((address from, address to, uint256 value));
event Approval((address owner, address spender, uint256 value));
event Mint((address to, uint256 amount));
event Burn((address from, uint256 amount));
event GovernanceKeyUpdated((bytes memory newKey));

function totalSupply() external returns (uint256) public {
return totalSupply;
}

function balanceOf(address account) external returns (uint256) public {
return balanceOf[account];
}

function transfer(address to, uint256 amount) external returns (bool) public {
require(to != Address(0), "Transfer to zero address");
require(balanceOf[msg.sender] >= amount, "Insufficient balance");
balanceOf[msg.sender] = balanceOf[msg.sender] - amount;
balanceOf[to] = balanceOf[to] + amount;
emit Transfer((msg.sender, to, amount));
return true;
}

function transferFrom(address from, address to, uint256 amount) external returns (bool) public {
require(to != Address(0), "Transfer to zero address");
require(balanceOf[from] >= amount, "Insufficient balance");
require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
balanceOf[from] = balanceOf[from] - amount;
balanceOf[to] = balanceOf[to] + amount;
allowance[from][msg.sender] = allowance[from][msg.sender] - amount;
emit Transfer((from, to, amount));
return true;
}

function approve(address spender, uint256 amount) external returns (bool) public {
require(spender != Address(0), "Approve to zero address");
allowance[msg.sender][spender] = amount;
emit Approval((msg.sender, spender, amount));
return true;
}

function allowance(address owner, address spender) external returns (uint256) public {
return allowance[owner][spender];
}

function increaseAllowance(address spender, uint256 addedValue) external returns (bool) public {
require(spender != Address(0), "Approve to zero address");
allowance[msg.sender][spender] = allowance[msg.sender][spender] + addedValue;
emit Approval((msg.sender, spender, allowance[msg.sender][spender]));
return true;
}

function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) public {
require(spender != Address(0), "Approve to zero address");
require(allowance[msg.sender][spender] >= subtractedValue, "Decreased allowance below zero");
allowance[msg.sender][spender] = allowance[msg.sender][spender] - subtractedValue;
emit Approval((msg.sender, spender, allowance[msg.sender][spender]));
return true;
}

// @gas_cost
function mint(address to, uint256 amount, bytes messageToSign, bytes memory signature) public // @gas_cost() {
require(to != Address(0), "Mint to zero address");
require(amount > 0, "Mint amount must be positive");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(governanceKey, messageToSign, signature);
require(isValid, "Invalid governance signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
totalSupply = totalSupply + amount;
balanceOf[to] = balanceOf[to] + amount;
emit Mint((to, amount));
emit Transfer((Address(0), to, amount));
}

function burn(uint256 amount) public {
require(balanceOf[msg.sender] >= amount, "Insufficient balance to burn");
require(amount > 0, "Burn amount must be positive");
balanceOf[msg.sender] = balanceOf[msg.sender] - amount;
totalSupply = totalSupply - amount;
emit Burn((msg.sender, amount));
emit Transfer((msg.sender, Address(0), amount));
}

function burnFrom(address from, uint256 amount) public {
require(balanceOf[from] >= amount, "Insufficient balance to burn");
require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
require(amount > 0, "Burn amount must be positive");
balanceOf[from] = balanceOf[from] - amount;
allowance[from][msg.sender] = allowance[from][msg.sender] - amount;
totalSupply = totalSupply - amount;
emit Burn((from, amount));
emit Transfer((from, Address(0), amount));
}

// @gas_cost
function pause(bytes messageToSign, bytes memory signature) public // @gas_cost() {
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(governanceKey, messageToSign, signature);
require(isValid, "Invalid governance signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
paused = true;
}

// @gas_cost
function unpause(bytes messageToSign, bytes memory signature) public // @gas_cost() {
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(governanceKey, messageToSign, signature);
require(isValid, "Invalid governance signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
paused = false;
}

function transfer(address to, uint256 amount) external returns (bool) public {
require(!paused, "Token transfers are paused");
require(to != Address(0), "Transfer to zero address");
require(balanceOf[msg.sender] >= amount, "Insufficient balance");
balanceOf[msg.sender] = balanceOf[msg.sender] - amount;
balanceOf[to] = balanceOf[to] + amount;
emit Transfer((msg.sender, to, amount));
return true;
}

// @gas_cost
function updateGovernanceKey(bytes memory newKey, bytes messageToSign, bytes memory signature) public // @gas_cost() {
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(governanceKey, messageToSign, signature);
require(isValid, "Invalid governance signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
governanceKey = newKey;
emit GovernanceKeyUpdated((newKey));
}

// @gas_cost
function batchTransfer(address[] recipients, uint256[] amounts) external returns (bool) public // @gas_cost() {
require(recipients.length == amounts.length, "Array length mismatch");
require(recipients.length > 0, "Empty arrays");
require(recipients.length <= 100, "Too many recipients");
uint256 totalAmount = 0;
for (uint256 i = 0; i < recipients.length; i++) {
totalAmount = totalAmount + amounts[i];
}
require(balanceOf[msg.sender] >= totalAmount, "Insufficient balance for batch");
for (uint256 i = 0; i < recipients.length; i++) {
require(recipients[i] != Address(0), "Invalid recipient address");
balanceOf[msg.sender] = balanceOf[msg.sender] - amounts[i];
balanceOf[recipients[i]] = balanceOf[recipients[i]] + amounts[i];
emit Transfer((msg.sender, recipients[i], amounts[i]));
}
return true;
}

function getTokenInfo() external returns (Tuple) public {
return (name, symbol, decimals, totalSupply);
}

}

