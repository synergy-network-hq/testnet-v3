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

contract PQCEscrow {
mapping(uint256 => Escrow) public escrows;
mapping(address => uint256[]) public buyerEscrows;
mapping(address => uint256[]) public sellerEscrows;
uint256 public escrowCount;
bytes memory public arbitratorKey;
mapping(uint256 => address) public disputeRaisedBy;
mapping(uint256 => bool) public disputeResolved;

constructor(bytes memory _arbitratorKey) {
arbitratorKey = _arbitratorKey;
escrowCount = 0;
}

event EscrowCreated((uint256 id, address buyer, address seller, uint256 amount));
event EscrowReleased((uint256 id, address recipient));
event EscrowRefunded((uint256 id, address recipient));
event EscrowDisputed((uint256 id, address raisedBy));
event EscrowExpired((uint256 id));
event DisputeResolved((uint256 id, bool favorBuyer));

function createEscrow(address seller, string description, uint256 duration, bytes memory releaseKey) external returns (uint256) public {
require(seller != Address(0), "Invalid seller");
require(seller != msg.sender, "Cannot escrow to self");
require(duration > 0, "Invalid duration");
uint256 id = escrowCount;
escrowCount = escrowCount + 1;
uint256 createdAt = block.number;
uint256 expiresAt = createdAt + duration;
escrows[id] = Escrow(        {
                    id: id,
                    buyer: msg.sender,
                    seller: seller,
                    amount: msg.value, // In real implementation, would transfer tokens
                    description: description,
                    createdAt: createdAt,
                    expiresAt: expiresAt,
                    status: EscrowStatus.Pending,
                    releaseData: Bytes(""),
                    releaseKey: releaseKey
                });
buyerEscrows[msg.sender].push(id);
sellerEscrows[seller].push(id);
emit EscrowCreated((id, msg.sender, seller, msg.value));
return id;
}

// @gas_cost
function releaseEscrow(uint256 escrowId, bytes messageToSign, bytes memory signature) public // @gas_cost() {
Escrow escrow = escrows[escrowId];
require(escrow.id == escrowId, "Escrow does not exist");
require(escrow.status == EscrowStatus.Pending, "Escrow not pending");
require(msg.sender == escrow.seller, "Only seller can release");
require(block.number <= escrow.expiresAt, "Escrow expired");
require(!disputeResolved[escrowId], "Escrow under dispute");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(escrow.releaseKey, messageToSign, signature);
require(isValid, "Invalid release signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
escrow.status = EscrowStatus.Released;
emit EscrowReleased((escrowId, escrow.seller));
}

function refundEscrow(uint256 escrowId) public {
Escrow escrow = escrows[escrowId];
require(escrow.id == escrowId, "Escrow does not exist");
require(escrow.status == EscrowStatus.Pending, "Escrow not pending");
require(msg.sender == escrow.buyer, "Only buyer can refund");
require(block.number > escrow.expiresAt, "Escrow not expired");
require(!disputeResolved[escrowId], "Escrow under dispute");
escrow.status = EscrowStatus.Refunded;
emit EscrowRefunded((escrowId, escrow.buyer));
}

function raiseDispute(uint256 escrowId) public {
Escrow escrow = escrows[escrowId];
require(escrow.id == escrowId, "Escrow does not exist");
require(escrow.status == EscrowStatus.Pending, "Escrow not pending");
require(msg.sender == escrow.buyer || msg.sender == escrow.seller, "Not party to escrow");
require(!disputeResolved[escrowId], "Dispute already resolved");
escrow.status = EscrowStatus.Disputed;
disputeRaisedBy[escrowId] = msg.sender;
emit EscrowDisputed((escrowId, msg.sender));
}

// @gas_cost
function resolveDispute(uint256 escrowId, bool favorBuyer, bytes messageToSign, bytes memory signature) public // @gas_cost() {
Escrow escrow = escrows[escrowId];
require(escrow.id == escrowId, "Escrow does not exist");
require(escrow.status == EscrowStatus.Disputed, "Escrow not disputed");
require(!disputeResolved[escrowId], "Dispute already resolved");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(arbitratorKey, messageToSign, signature);
require(isValid, "Invalid arbitrator signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
disputeResolved[escrowId] = true;
if (favorBuyer) {
escrow.status = EscrowStatus.Refunded;
emit EscrowRefunded((escrowId, escrow.buyer));
} else {
escrow.status = EscrowStatus.Released;
emit EscrowReleased((escrowId, escrow.seller));
}
emit DisputeResolved((escrowId, favorBuyer));
}

function checkExpiration(uint256 escrowId) public {
Escrow escrow = escrows[escrowId];
require(escrow.id == escrowId, "Escrow does not exist");
require(escrow.status == EscrowStatus.Pending, "Escrow not pending");
require(block.number > escrow.expiresAt, "Escrow not expired");
escrow.status = EscrowStatus.Expired;
emit EscrowExpired((escrowId));
}

function getEscrow(uint256 escrowId) external returns (Tuple) public {
Escrow escrow = escrows[escrowId];
return         (
                    escrow.id,
                    escrow.buyer,
                    escrow.seller,
                    escrow.amount,
                    escrow.description,
                    escrow.createdAt,
                    escrow.expiresAt,
                    escrow.status
                );
}

function getBuyerEscrows(address buyer) external returns (uint256[]) public {
return buyerEscrows[buyer];
}

function getSellerEscrows(address seller) external returns (uint256[]) public {
return sellerEscrows[seller];
}

// @gas_cost
function updateArbitratorKey(bytes memory newKey, bytes messageToSign, bytes memory signature) public // @gas_cost() {
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(arbitratorKey, messageToSign, signature);
require(isValid, "Invalid arbitrator signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
arbitratorKey = newKey;
}

function timeRemaining(uint256 escrowId) external returns (uint256) public {
Escrow escrow = escrows[escrowId];
if (block.number >= escrow.expiresAt) {
return 0;
}
return escrow.expiresAt - block.number;
}

function isExpired(uint256 escrowId) external returns (bool) public {
Escrow escrow = escrows[escrowId];
return block.number > escrow.expiresAt;
}

}

