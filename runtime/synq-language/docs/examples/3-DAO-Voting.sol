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

contract PQCGovernanceDAO {
address public tokenContract;
uint256 public proposalThreshold;
uint256 public votingPeriod;
uint256 public quorum;
bytes memory public governanceKey;
mapping(uint256 => Proposal) public proposals;
mapping(uint256 => mapping(address => bool)) public hasVoted;
mapping(uint256 => mapping(address => uint8)) public votes;
uint256 public proposalCount;

constructor(address _tokenContract, uint256 _proposalThreshold, uint256 _votingPeriod, uint256 _quorum, bytes memory _governanceKey) {
tokenContract = _tokenContract;
proposalThreshold = _proposalThreshold;
votingPeriod = _votingPeriod;
quorum = _quorum;
governanceKey = _governanceKey;
proposalCount = 0;
}

event ProposalCreated((uint256 id, address proposer, string description, uint256 startBlock, uint256 endBlock));
event VoteCast((uint256 proposalId, address voter, uint8 support, uint256 weight));
event ProposalExecuted((uint256 id));
event ProposalCanceled((uint256 id));
event GovernanceKeyUpdated((bytes memory newKey));
event QuorumUpdated((uint256 oldQuorum, uint256 newQuorum));

function propose(string description, address target, bytes calldata) external returns (uint256) public {
uint256 proposalId = proposalCount;
proposalCount = proposalCount + 1;
uint256 startBlock = block.number;
uint256 endBlock = startBlock + votingPeriod;
proposals = Proposal(        {
                    id: proposalId,
                    proposer: msg.sender,
                    description: description,
                    startBlock: startBlock,
                    endBlock: endBlock,
                    forVotes: 0,
                    againstVotes: 0,
                    abstainVotes: 0,
                    executed: false,
                    canceled: false,
                    calldata: calldata,
                    target: target
                });
emit ProposalCreated((proposalId, msg.sender, description, startBlock, endBlock));
return proposalId;
}

function castVote(uint256 proposalId, uint8 support) public {
require(support <= 2, "Invalid vote type");
require(proposals[proposalId].id == proposalId, "Proposal does not exist");
require(!proposals[proposalId].canceled, "Proposal is canceled");
require(!proposals[proposalId].executed, "Proposal already executed");
require(block.number >= proposals[proposalId].startBlock, "Voting not started");
require(block.number <= proposals[proposalId].endBlock, "Voting period ended");
require(!hasVoted[proposalId][msg.sender], "Already voted");
uint256 weight = 1;
hasVoted = true;
votes = support;
if (support == 1) {
proposals = proposals[proposalId].forVotes + weight;
} else {
if (support == 0) {
proposals = proposals[proposalId].againstVotes + weight;
} else {
proposals = proposals[proposalId].abstainVotes + weight;
}
}
emit VoteCast((proposalId, msg.sender, support, weight));
}

// @gas_cost
function castVoteWithSignature(uint256 proposalId, uint8 support, address voter, bytes memory voterKey, bytes messageToSign, bytes memory signature) public // @gas_cost() {
require(support <= 2, "Invalid vote type");
require(proposals[proposalId].id == proposalId, "Proposal does not exist");
require(!proposals[proposalId].canceled, "Proposal is canceled");
require(!proposals[proposalId].executed, "Proposal already executed");
require(block.number >= proposals[proposalId].startBlock, "Voting not started");
require(block.number <= proposals[proposalId].endBlock, "Voting period ended");
require(!hasVoted[proposalId][voter], "Already voted");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(voterKey, messageToSign, signature);
require(isValid, "Invalid signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
uint256 weight = 1;
hasVoted = true;
votes = support;
if (support == 1) {
proposals = proposals[proposalId].forVotes + weight;
} else {
if (support == 0) {
proposals = proposals[proposalId].againstVotes + weight;
} else {
proposals = proposals[proposalId].abstainVotes + weight;
}
}
emit VoteCast((proposalId, voter, support, weight));
}

// @gas_cost
function executeProposal(uint256 proposalId, bytes messageToSign, bytes memory signature) public // @gas_cost() {
Proposal proposal = proposals[proposalId];
require(proposal.id == proposalId, "Proposal does not exist");
require(!proposal.executed, "Proposal already executed");
require(!proposal.canceled, "Proposal is canceled");
require(block.number > proposal.endBlock, "Voting period not ended");
uint256 totalVotes = proposal.forVotes + proposal.againstVotes + proposal.abstainVotes;
require(totalVotes >= quorum, "Quorum not met");
require(proposal.forVotes > proposal.againstVotes, "Proposal did not pass");
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(governanceKey, messageToSign, signature);
require(isValid, "Invalid governance signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
proposal = true;
emit ProposalExecuted((proposalId));
}

function cancelProposal(uint256 proposalId) public {
Proposal proposal = proposals[proposalId];
require(proposal.id == proposalId, "Proposal does not exist");
require(!proposal.executed, "Proposal already executed");
require(!proposal.canceled, "Proposal already canceled");
require(msg.sender == proposal.proposer || msg.sender == Address(0), "Not authorized to cancel");
proposal = true;
emit ProposalCanceled((proposalId));
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
function updateQuorum(uint256 newQuorum, bytes messageToSign, bytes memory signature) public // @gas_cost() {
{
// SynQ require_pqc compatibility block
bool __synq_pqc_ok = true;
uint256 isValid = verifyMLDSASignature(governanceKey, messageToSign, signature);
require(isValid, "Invalid governance signature");
if (!__synq_pqc_ok) {
revert("PQC verification failed");
}
}
uint256 oldQuorum = quorum;
quorum = newQuorum;
emit QuorumUpdated((oldQuorum, newQuorum));
}

function getProposal(uint256 proposalId) external returns (Tuple) public {
Proposal proposal = proposals[proposalId];
return         (
                    proposal.id,
                    proposal.proposer,
                    proposal.description,
                    proposal.startBlock,
                    proposal.endBlock,
                    proposal.forVotes,
                    proposal.againstVotes,
                    proposal.abstainVotes,
                    proposal.executed,
                    proposal.canceled
                );
}

function hasVotedOn(uint256 proposalId, address voter) external returns (bool) public {
return hasVoted[proposalId][voter];
}

function getVote(uint256 proposalId, address voter) external returns (uint8) public {
return votes[proposalId][voter];
}

function getProposalState(uint256 proposalId) external returns (string) public {
Proposal proposal = proposals[proposalId];
if (proposal.canceled) {
return "Canceled";
}
if (proposal.executed) {
return "Executed";
}
if (block.number < proposal.startBlock) {
return "Pending";
}
if (block.number <= proposal.endBlock) {
return "Active";
}
if (proposal.forVotes <= proposal.againstVotes) {
return "Defeated";
}
if ((proposal.forVotes + proposal.againstVotes + proposal.abstainVotes) < quorum) {
return "QuorumNotMet";
}
return "Succeeded";
}

}

