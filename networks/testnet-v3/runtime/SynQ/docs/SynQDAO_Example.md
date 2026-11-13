// QuantumDAO Smart Contract – Full PQC Version

@deploy
contract QuantumDAO {

    // --------------------
    // STRUCTS
    // --------------------
    struct Proposal {
        id: UInt256,
        proposer: Address,
        data: Bytes,
        timestamp: UInt256,
        executed: Bool,
        votes_for: UInt256,
        votes_against: UInt256
    }

    struct Member {
        auth: PQAuth,
        weight: UInt256,
        last_active: UInt256
    }

    // --------------------
    // STATE
    // --------------------
    owner: Address
    admin_key: DilithiumKeyPair<3>
    vote_key: KyberKeyPair<768>
    members: mapping<Address, Member>
    proposals: mapping<UInt256, Proposal>
    encrypted_votes: mapping<UInt256, mapping<Address, KyberCiphertext<768>>>
    has_voted: mapping<UInt256, mapping<Address, Bool>>
    next_proposal_id: UInt256
    quorum: UInt256

    // --------------------
    // EVENTS
    // --------------------
    event MemberAdded(addr: Address, auth: PQAuth)
    event ProposalCreated(id: UInt256, proposer: Address)
    event VoteCast(id: UInt256, voter: Address)
    event ProposalExecuted(id: UInt256)

    // --------------------
    // CONSTRUCTOR
    // --------------------
    constructor(
        admin: Address,
        admin_auth: PQAuth,
        initial_members: Address[],
        initial_auths: PQAuth[],
        quorum_threshold: UInt256
    ) @gas_cost(base: 100_000) {
        require(initial_members.length == initial_auths.length, "Mismatch");

        owner = admin;
        admin_key = admin_auth.dilithium_key;
        vote_key = kyber_generate_keypair<768>();
        quorum = quorum_threshold;
        next_proposal_id = 1;

        for (i in 0 .. initial_members.length) {
            members[initial_members[i]] = Member(auth: initial_auths[i], weight: 1, last_active: block.timestamp);
            emit MemberAdded(initial_members[i], initial_auths[i]);
        }
    }

    // --------------------
    // ADD MEMBER
    // --------------------
    @public
    function add_member(
        addr: Address,
        new_auth: PQAuth,
        admin_sig: DilithiumSignature<3>,
        admin_falcon_sig: FalconSignature<1024>
    ) authenticated_pqc(admin_key, abi.encode("ADD_MEMBER:", addr, new_auth), admin_sig, admin_falcon_sig)
      @gas_cost(base: 60_000) {
        require(members[addr] == null, "Exists");

        members[addr] = Member(auth: new_auth, weight: 1, last_active: block.timestamp);
        emit MemberAdded(addr, new_auth);
    }

    // --------------------
    // CREATE PROPOSAL
    // --------------------
    @public
    function submit_proposal(
        data: Bytes,
        sig: DilithiumSignature<3>,
        sig2: FalconSignature<1024>
    ) @gas_cost(base: 75_000, dilithium_verify: 35_000) {
        let msg = abi.encode("PROPOSAL:", data);
        require_pqc {
            verify_composite_auth(msg, sig, sig2, members[msg.sender].auth)
        } or revert("Bad sig");

        let id = next_proposal_id;
        proposals[id] = Proposal(id: id, proposer: msg.sender, data: data, timestamp: block.timestamp, executed: false, votes_for: 0, votes_against: 0);
        next_proposal_id += 1;
        emit ProposalCreated(id, msg.sender);
    }

    // --------------------
    // VOTE ENCRYPTED
    // --------------------
    @public
    function cast_vote(
        proposal_id: UInt256,
        encrypted_vote: KyberCiphertext<768>,
        sig: FalconSignature<1024>
    ) @gas_cost(base: 45_000) {
        require(proposals[proposal_id].id != 0, "Invalid proposal");
        require(!has_voted[proposal_id][msg.sender], "Already voted");

        let vote_msg = abi.encode("VOTE:", proposal_id, msg.sender);
        require(verify_falcon(vote_msg, sig, members[msg.sender].auth.falcon_key), "Bad vote sig");

        encrypted_votes[proposal_id][msg.sender] = encrypted_vote;
        has_voted[proposal_id][msg.sender] = true;
        emit VoteCast(proposal_id, msg.sender);
    }

    // --------------------
    // TALLY BATCHED VOTES
    // --------------------
    @public
    @optimize_gas
    function tally_votes(
        proposal_id: UInt256,
        voters: Address[]
    ) @gas_cost(base: 60_000, per_vote: 20_000) with_gas_limit(voters.length * 25_000) {
        let yes = 0;
        let no = 0;

        for (v in voters) {
            let cipher = encrypted_votes[proposal_id][v];
            let plain = kyber_decapsulate<768>(cipher, vote_key);
            if (parse_vote(plain) == true) {
                yes += members[v].weight;
            } else {
                no += members[v].weight;
            }
        }

        if (yes + no >= quorum && yes > no) {
            proposals[proposal_id].executed = true;
            emit ProposalExecuted(proposal_id);
        }
    }

    // --------------------
    // GOVERNANCE KEY ROTATION
    // --------------------
    @public
    function rotate_governance_key(
        new_key: DilithiumKeyPair<3>,
        sig: DilithiumSignature<3>
    ) @gas_cost(base: 50_000) {
        let msg = abi.encode("ROTATE:", new_key);
        require(verify_dilithium(msg, sig, admin_key), "Bad admin sig");
        admin_key = new_key;
    }
}

// Helper parser
function parse_vote(vote_bytes: Bytes) -> Bool {
    if (vote_bytes == Bytes("YES")) return true;
    else return false;
}
