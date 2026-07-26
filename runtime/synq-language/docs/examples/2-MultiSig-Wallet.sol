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

contract PQCMultiSigWallet {
address[] public owners;
uint256 public requiredSignatures;
uint256 public nonce;
mapping(uint256 => Transaction) public transactions;
mapping(uint256 => mapping(address => bool)) public confirmations;
mapping(address => bytes memory) public ownerKeys;
uint256 public transactionCount;

constructor(address[] _owners, bytes memory[] _ownerKeys, uint256 _requiredSignatures) {
require(_owners.length > 0, "No owners provided");
require(_requiredSignatures > 0, "Required signatures must be > 0");
require(_requiredSignatures <= _owners.length, "Too many required signatures");
require(_owners.length == _ownerKeys.length, "Owners and keys length mismatch");
owners = _owners;
requiredSignatures = _requiredSignatures;
nonce = 0;
transactionCount = 0;
for (uint256 i = 0; i < _owners.length; i++) {
ownerKeys[_owners[i]] = _ownerKeys[i];
}
}

event Deposit((address sender, uint256 value));
event TransactionSubmitted((uint256 txId, address to, uint256 value));
event TransactionConfirmed((uint256 txId, address owner));
event TransactionExecuted((uint256 txId));
event OwnerAdded((address owner, bytes memory key));
event OwnerRemoved((address owner));
event RequiredSignaturesChanged((uint256 oldRequired, uint256 newRequired));

function isOwner(address addr) external returns (bool) internal {
for (uint256 i = 0; i < owners.length; i++) {
if (owners[i] == addr) {
return true;
}
}
return false;
}

function deposit() public {
emit Deposit((msg.sender, msg.value));
}

function submitTransaction(address to, uint256 value, bytes data) external returns (uint256) public {
require(isOwner(msg.sender), "Not an owner");
require(to != Address(0), "Invalid recipient");
uint256 txId = transactionCount;
transactionCount = transactionCount + 1;
transactions[txId] = Transaction(        {
                    to: to,
                    value: value,
                    data: data,
                    executed: false,
                    confirmations: 0
                });
emit TransactionSubmitted((txId, to, value));
return txId;
}

// @gas_cost
function confirmTransaction(uint256 txId, bytes messageToSign, bytes memory signature) public // @gas_cost() {
require(isOwner(msg.sender), "Not an owner");
require(transactions[txId].to != Address(0), "Transaction does not exist");
require(!transactions[txId].executed, "Transaction already executed");
require(!confirmations[txId][msg.sender], "Transaction already confirmed");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(ownerKeys[msg.sender], messageToSign, signature);
require(isValid, "Invalid signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
confirmations[txId][msg.sender] = true;
transactions[txId].confirmations = transactions[txId].confirmations + 1;
emit TransactionConfirmed((txId, msg.sender));
if (transactions[txId].confirmations >= requiredSignatures) {
executeTransaction(txId);
}
}

function executeTransaction(uint256 txId) internal {
require(!transactions[txId].executed, "Transaction already executed");
require(transactions[txId].confirmations >= requiredSignatures, "Not enough confirmations");
Transaction tx = transactions[txId];
tx.executed = true;
emit TransactionExecuted((txId));
}

function revokeConfirmation(uint256 txId) public {
require(isOwner(msg.sender), "Not an owner");
require(transactions[txId].to != Address(0), "Transaction does not exist");
require(!transactions[txId].executed, "Transaction already executed");
require(confirmations[txId][msg.sender], "Transaction not confirmed");
confirmations[txId][msg.sender] = false;
transactions[txId].confirmations = transactions[txId].confirmations - 1;
}

// @gas_cost
function addOwner(address newOwner, bytes memory newOwnerKey, bytes messageToSign, bytes memory[] signatures) public // @gas_cost() {
require(!isOwner(newOwner), "Already an owner");
require(newOwner != Address(0), "Invalid owner address");
require(signatures.length >= requiredSignatures, "Not enough signatures");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 validSignatures = 0;
for (uint256 i = 0; i < signatures.length; i++) {
if (i < owners.length) {
uint256 isValid = verifyMLDSASignature(ownerKeys[owners[i]], messageToSign, signatures[i]);
if (isValid) {
validSignatures = validSignatures + 1;
}
}
}
require(validSignatures >= requiredSignatures, "Not enough valid signatures");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
owners.push(newOwner);
ownerKeys[newOwner] = newOwnerKey;
emit OwnerAdded((newOwner, newOwnerKey));
}

// @gas_cost
function removeOwner(address ownerToRemove, bytes messageToSign, bytes memory[] signatures) public // @gas_cost() {
require(isOwner(ownerToRemove), "Not an owner");
require(owners.length - 1 >= requiredSignatures, "Would violate required signatures");
require(signatures.length >= requiredSignatures, "Not enough signatures");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 validSignatures = 0;
for (uint256 i = 0; i < signatures.length; i++) {
if (i < owners.length) {
uint256 isValid = verifyMLDSASignature(ownerKeys[owners[i]], messageToSign, signatures[i]);
if (isValid) {
validSignatures = validSignatures + 1;
}
}
}
require(validSignatures >= requiredSignatures, "Not enough valid signatures");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
for (uint256 i = 0; i < owners.length; i++) {
if (owners[i] == ownerToRemove) {
owners[i] = owners[owners.length - 1];
owners.pop();
break;
}
}
emit OwnerRemoved((ownerToRemove));
}

// @gas_cost
function replaceOwner(address oldOwner, address newOwner, bytes memory newOwnerKey, bytes messageToSign, bytes memory[] signatures) public // @gas_cost() {
require(isOwner(oldOwner), "Old owner not found");
require(!isOwner(newOwner), "New owner already exists");
require(newOwner != Address(0), "Invalid new owner");
require(signatures.length >= requiredSignatures, "Not enough signatures");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 validSignatures = 0;
for (uint256 i = 0; i < signatures.length; i++) {
if (i < owners.length) {
uint256 isValid = verifyMLDSASignature(ownerKeys[owners[i]], messageToSign, signatures[i]);
if (isValid) {
validSignatures = validSignatures + 1;
}
}
}
require(validSignatures >= requiredSignatures, "Not enough valid signatures");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
for (uint256 i = 0; i < owners.length; i++) {
if (owners[i] == oldOwner) {
owners[i] = newOwner;
ownerKeys[newOwner] = newOwnerKey;
break;
}
}
emit OwnerRemoved((oldOwner));
emit OwnerAdded((newOwner, newOwnerKey));
}

// @gas_cost
function changeRequiredSignatures(uint256 newRequired, bytes messageToSign, bytes memory[] signatures) public // @gas_cost() {
require(newRequired > 0, "Required must be > 0");
require(newRequired <= owners.length, "Too many required");
require(signatures.length >= requiredSignatures, "Not enough signatures");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 validSignatures = 0;
for (uint256 i = 0; i < signatures.length; i++) {
if (i < owners.length) {
uint256 isValid = verifyMLDSASignature(ownerKeys[owners[i]], messageToSign, signatures[i]);
if (isValid) {
validSignatures = validSignatures + 1;
}
}
}
require(validSignatures >= requiredSignatures, "Not enough valid signatures");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
uint256 oldRequired = requiredSignatures;
requiredSignatures = newRequired;
emit RequiredSignaturesChanged((oldRequired, newRequired));
}

function getTransaction(uint256 txId) external returns (Tuple) public {
Transaction tx = transactions[txId];
return (tx.to, tx.value, tx.data, tx.executed, tx.confirmations);
}

function isConfirmedBy(uint256 txId, address owner) external returns (bool) public {
return confirmations[txId][owner];
}

function getOwners() external returns (address[]) public {
return owners;
}

function getOwnerCount() external returns (uint256) public {
return owners.length;
}

}

