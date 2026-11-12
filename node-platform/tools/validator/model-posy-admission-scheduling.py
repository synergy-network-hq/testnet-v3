#!/usr/bin/env python3
"""Gate A abstract scheduling contract, not an activated protocol or crypto proof.

verified_authorization is an explicit model assumption, not simulated signature
verification. Future-target authorization is a proposed amendment capability;
current envelopes remain bound. No timing/TPS or Gate C qualification is claimed.
The snapshot models durable owner transitions, not a production storage format.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
import copy
import argparse
import hashlib
import heapq
import json
import random
import sys
from pathlib import Path


class Rejected(ValueError):
    pass


@dataclass(frozen=True)
class Intent:
    transaction_id: str
    incarnation: str
    sender: str
    nonce: int
    protected_bytes: int
    min_target: int
    max_target: int
    expires_at: int
    fixed_target: int | None = None
    verified_authorization: bool = False


class SchedulingModel:
    def __init__(self, incarnation, max_count=4, max_bytes=1024):
        self.incarnation = incarnation
        self.max_count = max_count
        self.max_bytes = max_bytes
        self.records = {}
        self.closed = set()
        self.effects = {}
        self.nonces = {}
        self.finalized = {}
        self.availability_votes = {}

    def receive(self, intent, now):
        if (not intent.verified_authorization or intent.incarnation != self.incarnation
                or not intent.transaction_id or not intent.sender or intent.nonce < 0
                or not 0 < intent.protected_bytes <= self.max_bytes
                or intent.min_target < 1 or intent.max_target < intent.min_target
                or now >= intent.expires_at
                or (intent.fixed_target is not None
                    and not intent.min_target <= intent.fixed_target <= intent.max_target)):
            raise Rejected('invalid, expired or wrong-authority intent')
        old = self.records.get(intent.transaction_id)
        if old is not None:
            if old['intent'] != asdict(intent):
                raise Rejected('same identifier with conflicting authorization')
            return old['stage']
        for record in self.records.values():
            prior = record['intent']
            if prior['sender'] == intent.sender and prior['nonce'] == intent.nonce:
                raise Rejected('conflicting sender nonce')
        live = [r for r in self.records.values() if r['stage'] not in ('finalized', 'expired')]
        if len(live) >= self.max_count or sum(r['intent']['protected_bytes'] for r in live) + intent.protected_bytes > self.max_bytes:
            raise Rejected('explicit ingress backpressure')
        self.records[intent.transaction_id] = {'intent': asdict(intent), 'stage': 'durably-queued',
                                               'target': None, 'availability': False,
                                               'ordered': False, 'revealed': False}
        return 'durably-queued'

    def bind(self, transaction_id, target, now):
        r = self.records[transaction_id]
        intent = r['intent']
        if r['target'] is not None:
            if target != r['target']:
                raise Rejected('bound material cannot be retargeted')
            return r['stage']
        if now >= intent['expires_at']:
            r['stage'] = 'expired'
            raise Rejected('expired before target assignment')
        if (target in self.closed or not intent['min_target'] <= target <= intent['max_target']
                or intent['fixed_target'] not in (None, target)):
            raise Rejected('closed or unauthorized target')
        r['target'] = target
        r['stage'] = 'target-bound-admitted'
        return r['stage']

    def availability_vote(self, transaction_id, target, member, verified_authority):
        """Abstract durable vote, assuming authenticated authority verification.

        This model has one global cutoff instant. Real per-validator observations
        and delayed evidence delivery require the richer distributed Gate C model.
        """
        r = self.records[transaction_id]
        if (not verified_authority or member not in {0, 1, 2, 3, 4}
                or r['target'] != target):
            raise Rejected('invalid availability vote authority or target')
        votes = self.availability_votes.setdefault(transaction_id, set())
        if member in votes:
            return  # Exact durable retransmission remains valid after cutoff.
        if target in self.closed:
            raise Rejected('fresh availability vote after cutoff')
        votes.add(member)

    def availability(self, transaction_id, target, verified_members):
        r = self.records[transaction_id]
        members = set(verified_members)
        if (r['target'] != target or not members <= {0, 1, 2, 3, 4}
                or len(members) < 4
                or not members <= self.availability_votes.get(transaction_id, set())):
            raise Rejected('wrong target or insufficient authenticated availability')
        r['availability'] = True
        r['stage'] = 'availability-certified'

    def cutoff(self, target, verified_existing_vc):
        if not verified_existing_vc:
            raise Rejected('cutoff requires existing verified VC')
        self.closed.add(target)

    def order(self, transaction_id, target, verified_frontier):
        r = self.records[transaction_id]
        if r['target'] != target or target not in self.closed or not r['availability'] or not verified_frontier:
            raise Rejected('ordering without exact cutoff and available material')
        r['ordered'] = True
        r['stage'] = 'cutoff-fixed-ordered'

    def reveal(self, transaction_id, target, verified_parent_authority):
        r = self.records[transaction_id]
        if r['target'] != target or not r['ordered'] or not verified_parent_authority:
            raise Rejected('reveal without exact authorized ordered batch')
        r['revealed'] = True
        r['stage'] = 'authorized-reveal'

    def propose(self, transaction_id, target):
        r = self.records[transaction_id]
        if r['target'] != target or not (r['availability'] and r['ordered'] and r['revealed']):
            raise Rejected('queued material is not an executable candidate')
        return transaction_id, target

    def finalize(self, transaction_id, target, verified_qcs):
        self.propose(transaction_id, target)
        if set(verified_qcs) != {target, target + 1, target + 2}:
            raise Rejected('three-QC finality witness missing')
        if transaction_id in self.finalized:
            if self.finalized[transaction_id] != target:
                raise Rejected('conflicting finalized target')
            return
        r = self.records[transaction_id]
        sender = r['intent']['sender']
        nonce = r['intent']['nonce']
        if self.nonces.get(sender, 0) != nonce:
            raise Rejected('out-of-order or replayed execution nonce')
        self.effects[transaction_id] = self.effects.get(transaction_id, 0) + 1
        self.nonces[sender] = nonce + 1
        self.finalized[transaction_id] = target
        r['stage'] = 'finalized'

    def empty_candidate(self, target, verified_empty_material):
        if not verified_empty_material:
            raise Rejected('no uncertified empty candidate fallback')
        return target

    def snapshot(self):
        return copy.deepcopy(self.__dict__)

    @classmethod
    def restore(cls, snapshot):
        owner = cls(snapshot['incarnation'])
        owner.__dict__ = copy.deepcopy(snapshot)
        return owner


# Separate from proposed target-independent SchedulingModel. This contract
# exercises current target-bound material and never selects production timing.
MODEL_VERSION = 'posy-distributed-contract-v1'
ASSUMPTIONS = [
    'Cryptographic, proposer, protected frontier/reveal and execution verification are assumed predicates; native PQC is not modeled.',
    'Exactly five identities, equal participation and four-of-five quorum; the model does not define governed proposer selection.',
    'Each owner transition is atomic except explicitly staged fsync acknowledgements; durable writes do not disappear on supported restart.',
    'Safety holds during arbitrary finite drops/delays; liveness is checked only after an eventual bounded fair retry phase.',
    'Supported recovery history contains every missing parent/QC, and replay has a separate sufficient service budget.',
    'The clock is a deterministic event index, not milliseconds; no production timeout or cadence is inferred.',
    'Fresh admission remains bound to its original target; accepted admission is not a reservation or an availability guarantee.',
]
UNCOVERED_NATIVE = [
    'Genuine signature/KEM verification, provider errors, authority/Genesis decoding and native proposer resolution',
    'Operating-system thread scheduling, socket and disk failure modes, memory accounting, fsync implementation and shutdown races',
    'Actual ETDAG ordering/reveal/frontier proofs, application execution correctness and hostile Byzantine certificate structure',
    'Native epoch replacement, authority transition and journal namespace implementation',
    'Full PoSy locking/proposer rules and Byzantine fork exploration; this campaign uses one authenticated canonical proposal ancestry',
    'Native finalized-source/lookahead derivation and signed context bytes; model targets are symbols, not selected production parameters',
    'Catch-up throughput, resource contention, retained-history size limits, measured admission/cadence/TPS and five-host qualification',
]


@dataclass(frozen=True)
class CampaignConfig:
    first_seed: int = 0
    seeds: int = 10000
    max_events_per_seed: int = 2000
    max_network_queue: int = 4096
    trace_limit: int = 256
    retention_heights: int = 64
    block_count: int = 18

    def validate(self):
        if (not 0 <= self.first_seed < 2**63 or not 1 <= self.seeds <= 10000
                or self.first_seed + self.seeds > 2**63
                or not 256 <= self.max_events_per_seed <= 10000
                or not 64 <= self.max_network_queue <= 4096
                or not 32 <= self.trace_limit <= 1024
                or not 18 <= self.block_count <= 64
                or self.retention_heights < self.block_count + 2
                or self.retention_heights > 128):
            raise Rejected('campaign bounds or supported retention invalid')


@dataclass(frozen=True)
class BoundTransfer:
    transaction_id: str
    incarnation: str
    sender: str
    nonce: int
    target: int
    protected_bytes: int = 200
    verified: bool = True


class ContractViolation(AssertionError):
    pass


class DistributedOwner:
    def __init__(self, member, incarnation='qualification', epoch=1):
        self.member=member;self.incarnation=incarnation;self.epoch=epoch;self.generation=1
        self.online=True;self.closed=set();self.staged={};self.accepted=set();self.excluded=set()
        self.availability_journal={};self.published_availability=set();self.consensus_signing={};self.timeout_signing=set()
        self.qcs={};self.rounds={};self.finalized={};self.effects={};self.nonces={}
        self.corrupt=False;self.worker_results=0

    def healthy(self):
        if self.corrupt:raise Rejected('durable corruption fails closed')
        if not self.online:raise Rejected('owner offline')

    def stage(self, transfer):
        self.healthy()
        if (not transfer.verified or transfer.incarnation!=self.incarnation or transfer.target<3 or transfer.nonce<0
                or not transfer.transaction_id or len(transfer.transaction_id)>128
                or not transfer.sender or len(transfer.sender)>128 or not 0<transfer.protected_bytes<=8192):
            raise Rejected('wrong authority or invalid bound transfer')
        prior=self.staged.get(transfer.transaction_id)
        if prior is not None:
            if prior!=transfer:raise Rejected('conflicting duplicate identity')
            return self.receipt(transfer.transaction_id)
        if transfer.target in self.closed:raise Rejected('closed target')
        if any(t.sender==transfer.sender and t.nonce==transfer.nonce for t in self.staged.values()):
            raise Rejected('conflicting nonce')
        if len(self.staged)>=16 or sum(t.protected_bytes for t in self.staged.values())+transfer.protected_bytes>8192:
            raise Rejected('explicit admission backpressure')
        self.staged[transfer.transaction_id]=transfer
        return 'staged'

    def fsync_ack(self, transaction_id):
        self.healthy();transfer=self.staged[transaction_id]
        if transaction_id in self.accepted:return 'accepted'
        # No lock/reservation delays VC. A native staged vertex is not a receipt.
        if transfer.target in self.closed:
            self.excluded.add(transaction_id);return 'rejected_closed'
        self.accepted.add(transaction_id);return 'accepted'

    def receipt(self, transaction_id):
        if transaction_id in self.accepted:return 'accepted'
        if transaction_id in self.excluded:return 'rejected_closed'
        return 'staged' if transaction_id in self.staged else 'unknown'

    def observe_vc(self, target, verified=True):
        self.healthy()
        if not verified:raise Rejected('unverified VC cannot close target')
        self.closed.add(target)

    def sign_availability(self, transaction_id):
        self.healthy();transfer=self.staged[transaction_id]
        if transaction_id in self.availability_journal:return
        if transaction_id not in self.accepted or transfer.target in self.closed:
            raise Rejected('fresh availability signing after cutoff or before admission')
        self.availability_journal[transaction_id]=(transfer.target,self.incarnation)

    def availability_fsync_ack(self, transaction_id):
        self.healthy();transfer=self.staged[transaction_id]
        if transaction_id not in self.availability_journal:raise Rejected('signature not staged')
        if transaction_id in self.published_availability:return True
        if transfer.target in self.closed:return False
        self.published_availability.add(transaction_id);return True

    def restore(self):
        # Recovery keeps all journals; closed staging never manufactures acceptance.
        retained=copy.deepcopy(self.__dict__)
        owner=DistributedOwner(self.member)
        owner.__dict__=retained
        for txid,transfer in owner.staged.items():
            if txid not in owner.accepted and transfer.target in owner.closed:
                owner.excluded.add(txid)
        return owner

    def sign_consensus(self,height,round_number,block_id,verified_material=True):
        self.healthy()
        if not verified_material or height<1 or round_number!=self.rounds.get(height,0):
            raise Rejected('unverified material or unauthorized local round')
        key=(height,round_number)
        prior=self.consensus_signing.get(key)
        if prior is not None and prior!=block_id:raise Rejected('contradictory signing fails closed')
        self.consensus_signing[key]=block_id
        return (self.member,height,round_number,block_id,self.incarnation,self.epoch)

    def timeout(self,height,round_number):
        self.healthy()
        if round_number!=self.rounds.get(height,0):raise Rejected('wrong timeout round')
        self.timeout_signing.add((height,round_number))
        return (self.member,height,round_number,self.incarnation,self.epoch)

    def accept_tc(self,height,round_number,statements):
        self.healthy()
        if len({s[0] for s in statements})<4 or any(s[0] not in range(5) or s[1:]!=(height,round_number,self.incarnation,self.epoch) for s in statements):
            raise Rejected('timeout advancement lacks verified four-of-five evidence')
        self.rounds[height]=max(self.rounds.get(height,0),round_number+1)

    def accept_qc(self,qc):
        self.healthy()
        height=qc['height'];votes=qc['votes']
        if (qc['incarnation']!=self.incarnation or qc['epoch']!=self.epoch or not qc['verified']
                or len({v[0] for v in votes})<4
                or any(v[0] not in range(5) or v[1:]!=(height,qc['round'],qc['block_id'],self.incarnation,self.epoch) for v in votes)):
            raise Rejected('QC lacks exact four-of-five verified authority')
        prior=self.qcs.get(height)
        if prior is not None and prior['block_id']!=qc['block_id']:raise Rejected('conflicting QC')
        self.qcs[height]=copy.deepcopy(qc)
        self._advance_finality()

    def _advance_finality(self):
        # Out-of-order delivery remains observation only until linked ancestry.
        next_height=max(self.finalized,default=0)+1
        while all(h in self.qcs for h in (next_height,next_height+1,next_height+2)):
            a,b,c=(self.qcs[h] for h in (next_height,next_height+1,next_height+2))
            expected_parent='genesis' if next_height==1 else self.finalized[next_height-1]
            if a['parent']!=expected_parent or b['parent']!=a['block_id'] or c['parent']!=b['block_id']:return
            for transfer in a['transfers']:
                if transfer.target!=a['height'] or transfer.incarnation!=self.incarnation:
                    raise Rejected('wrong target/incarnation at execution')
                if transfer.transaction_id in self.effects:raise Rejected('transaction ordered twice')
                if self.nonces.get(transfer.sender,0)!=transfer.nonce:raise Rejected('execution nonce replay/gap')
                self.effects[transfer.transaction_id]=1;self.nonces[transfer.sender]=transfer.nonce+1
            self.finalized[next_height]=a['block_id'];next_height+=1

    def accept_worker(self,tag,verified=True):
        if tag!=(self.incarnation,self.epoch,self.generation) or not verified:return False
        self.healthy();self.worker_results+=1;return True


class DistributedContractModel:
    def __init__(self,seed,config=None):
        self.config=config or CampaignConfig(seeds=1);self.config.validate()
        self.seed=seed;self.random=random.Random(seed);self.owners=[DistributedOwner(i) for i in range(5)]
        self.trace=[];self.events=0;self.queue=[];self.sequence=0;self.clock=0;self.drops=0;self.rejections=0
        self.coverage=set();self.history={};self.published_votes={};self.published_timeouts={}

    def record(self,event,**details):
        self.events+=1
        if self.events>self.config.max_events_per_seed:raise ContractViolation('event bound exhausted before proof completion')
        self.trace.append({'step':self.events,'tick':self.clock,'event':event,**details})
        if len(self.trace)>self.config.trace_limit:self.trace.pop(0)

    def rejected(self,fn,category):
        try:fn()
        except Rejected:self.rejections+=1;self.coverage.add(category);self.record('expected_rejection',category=category);return
        raise ContractViolation('invalid transition accepted: '+category)

    def deliver(self,qc,member):
        if len(self.queue)>=self.config.max_network_queue:raise Rejected('network backpressure')
        self.sequence+=1
        heapq.heappush(self.queue,(self.clock+self.random.randrange(8),self.sequence,member,qc))

    def drain(self,drop=False):
        while self.queue:
            tick,_,member,qc=heapq.heappop(self.queue);self.clock=tick
            if not self.owners[member].online or (drop and self.random.randrange(4)==0):
                self.drops+=1;self.record('network_drop',member=member,height=qc['height']);continue
            self.owners[member].accept_qc(qc);self.record('qc_delivery',member=member,height=qc['height'],round=qc['round'])

    def certificate(self,height,round_number,transfers):
        parent='genesis' if height==1 else self.history[height-1]['block_id']
        block_id=hashlib.sha256(json.dumps([self.owners[0].incarnation,height,parent,[asdict(t) for t in transfers]],sort_keys=True).encode()).hexdigest()
        for transfer in transfers:
            if transfer.target!=height or sum(transfer.transaction_id in o.published_availability for o in self.owners)<4:
                raise Rejected('nonempty proposal lacks exact target and retained availability quorum')
            if sum(height in o.closed for o in self.owners if o.online)<4:
                raise Rejected('protected order lacks local verified cutoff observations')
            # The exact authenticated frontier and subsequent reveal VC are
            # assumed native predicates, not implied by these availability votes.
        votes=[]
        for owner in self.owners:
            if owner.online:
                vote=owner.sign_consensus(height,round_number,block_id)
                self.published_votes[(owner.member,height,round_number)]=vote;votes.append(vote)
                self.record('durable_vote',member=owner.member,height=height,round=round_number)
        if len(votes)<4:raise Rejected('below quorum; no QC or finality')
        qc={'height':height,'round':round_number,'block_id':block_id,'parent':parent,'votes':tuple(votes),
            'incarnation':self.owners[0].incarnation,'epoch':self.owners[0].epoch,'transfers':tuple(transfers),'verified':True}
        self.history[height]=qc;return qc

    def admission_races(self):
        transfer=BoundTransfer('raced','qualification','raced-wallet',0,6)
        events=[]
        for member in range(5):
            write=self.random.randrange(3);ack=write+1+self.random.randrange(3);close=2+self.random.randrange(5)
            events.extend([(write,self.random.random(),'stage',member),(ack,self.random.random(),'ack',member),
                (close,self.random.random(),'close',member),(ack+1,self.random.random(),'vote',member),
                (ack+2,self.random.random(),'vote_ack',member)])
        for tick,_,kind,member in sorted(events):
            self.clock=tick;owner=self.owners[member]
            try:
                if kind=='stage':owner.stage(transfer)
                elif kind=='ack':owner.fsync_ack(transfer.transaction_id)
                elif kind=='close':owner.observe_vc(6)
                elif kind=='vote':owner.sign_availability(transfer.transaction_id)
                elif kind=='vote_ack':owner.availability_fsync_ack(transfer.transaction_id)
            except (Rejected,KeyError):self.rejections+=1
            self.record('admission_'+kind,member=member,receipt=owner.receipt('raced'))
        self.coverage.update(['local_vc_delivery','fsync_cutoff_interleaving','fresh_signature_cutoff_guard','ambiguous_receipt_reconciliation'])
        for member,owner in enumerate(self.owners):
            self.owners[member]=owner=owner.restore();self.record('retained_admission_restart',member=member)
            if 6 not in owner.closed:owner.observe_vc(6)
            if 'raced' in owner.staged and 'raced' not in owner.accepted and owner.receipt('raced')!='rejected_closed':
                raise ContractViolation('closed staged journal manufactured accepted receipt')
            self.rejected(lambda o=owner:o.stage(BoundTransfer('retarget','qualification','other',0,6)),'closed_target_rejected')
            if 'raced' in owner.staged:
                original=owner.receipt('raced');owner.stage(transfer)
                if owner.receipt('raced')!=original:raise ContractViolation('duplicate changed durable receipt')
                self.rejected(lambda o=owner:o.stage(BoundTransfer('raced','qualification','raced-wallet',1,6)),'conflicting_duplicate')
        return transfer if sum('raced' in o.published_availability for o in self.owners)>=4 else None

    def run(self):
        raced=self.admission_races()
        healthy=BoundTransfer('healthy','qualification','funded-wallet',0,12)
        for owner in self.owners:
            owner.stage(healthy);owner.fsync_ack('healthy');owner.sign_availability('healthy');owner.availability_fsync_ack('healthy')
        self.coverage.add('abstract_nonempty_batch_native_execution_uncovered')
        self.owners[3].online=False;self.owners[4].online=False
        before=[dict(o.finalized) for o in self.owners]
        self.rejected(lambda:self.certificate(1,0,()),'below_quorum_halt')
        if before!=[o.finalized for o in self.owners]:raise ContractViolation('below-quorum finality advanced')
        self.owners[3].online=True;self.record('fourth_restored')
        statements=[owner.timeout(1,0) for owner in self.owners if owner.online]
        for statement in statements:self.published_timeouts[(statement[0],1,0)]=statement
        self.rejected(lambda:self.owners[0].accept_tc(1,0,statements[:3]),'unauthorized_round_advancement')
        for owner in self.owners[:4]:owner.accept_tc(1,0,statements)
        self.coverage.update(['verified_timeout_round_alignment','fourth_validator_restoration'])
        for height in range(1,self.config.block_count+1):
            if height==12:
                for owner in self.owners[:4]:owner.observe_vc(12)
            transfers=(raced,) if height==6 and raced else ((healthy,) if height==12 else ())
            qc=self.certificate(height,1 if height==1 else 0,transfers)
            for member in range(4):self.deliver(qc,member)
            if height%3==0:self.drain(drop=True)
            # A restart retains the exact vote choice and timeout evidence.
            member=self.random.randrange(4);self.owners[member]=self.owners[member].restore()
            self.rejected(lambda m=member,h=height:self.owners[m].sign_consensus(h,1 if h==1 else 0,'conflict'),'durable_signing_conflict')
        self.drain(drop=True)
        self.coverage.update(['delayed_dropped_reordered_qc','restart_signing_persistence','three_qc_linked_finality'])
        # Fair retry is predeclared, does not erase a journal or manufacture QC.
        order=list(self.history);self.random.shuffle(order)
        for height in order:
            for member in range(4):self.deliver(self.history[height],member)
        self.drain(drop=False)
        four_height=max(self.owners[0].finalized,default=0)
        if four_height!=self.config.block_count-2:raise ContractViolation('four-node liveness failed under fair delivery')
        self.owners[4].online=True;self.record('fifth_rejoined')
        if 1<self.config.block_count-self.config.retention_heights:
            raise Rejected('unsupported historical retention; recovery cannot be claimed')
        order=list(self.history);self.random.shuffle(order)
        for height in order:self.deliver(self.history[height],4)
        self.drain(drop=False)
        expected_finalized=copy.deepcopy(self.owners[0].finalized);expected_effects=copy.deepcopy(self.owners[0].effects)
        if any(o.finalized!=expected_finalized or o.effects!=expected_effects or o.nonces!=self.owners[0].nonces for o in self.owners):
            raise ContractViolation('five-validator finality/execution disagreement after verified replay')
        if any(o.effects.get('healthy')!=1 for o in self.owners):raise ContractViolation('healthy nonempty cohort not exactly once')
        self.coverage.update(['fifth_validator_rejoin','common_finalized_commitment','nonce_exactly_once_execution','supported_retention_replay'])
        for owner in self.owners:
            old_tag=(owner.incarnation,owner.epoch,owner.generation)
            owner.generation+=1
            if owner.accept_worker(old_tag):raise ContractViolation('stale worker generation mutated owner')
            replacement_tag=(owner.incarnation+'-next',owner.epoch+1,owner.generation)
            if owner.accept_worker(replacement_tag):raise ContractViolation('foreign epoch worker mutated owner')
            owner.accept_worker((owner.incarnation,owner.epoch,owner.generation))
            replay_height=max(owner.finalized)
            owner.accept_qc(self.history[replay_height+2])
            if owner.effects!=expected_effects:raise ContractViolation('duplicate finality replay executed twice')
        self.coverage.update(['stale_worker_completion','epoch_authority_fencing','duplicate_qc_finality_idempotence'])
        self.rejected(lambda:self.owners[0].stage(BoundTransfer('foreign','old','foreign',0,20)),'wrong_incarnation_rejected')
        self.rejected(lambda:self.owners[0].stage(BoundTransfer('invalid','qualification','invalid',0,20,verified=False)),'invalid_authorization_rejected')
        corrupt=self.owners[0].restore();corrupt.corrupt=True
        self.rejected(lambda:corrupt.sign_consensus(19,0,'x'),'corruption_fail_closed_no_empty_restart')
        return {'seed':self.seed,'events':self.events,'drops':self.drops,'expected_rejections':self.rejections,
            'common_finalized_height':four_height,'effects':dict(expected_effects),'coverage':sorted(self.coverage)}


def run_campaign(config):
    config.validate();coverage={};totals={'events':0,'drops':0,'expected_rejections':0};completed=0;failure=None
    digest=hashlib.sha256()
    for seed in range(config.first_seed,config.first_seed+config.seeds):
        model=DistributedContractModel(seed,config)
        try:result=model.run()
        except Exception as error:
            failure={'seed':seed,'error_type':type(error).__name__,'error':str(error),
                'trace':model.trace,'trace_is_last_bounded_events':True,'reproduce':{'first_seed':seed,'seeds':1,**{k:v for k,v in asdict(config).items() if k not in ('first_seed','seeds')}}}
            break
        completed+=1
        for key in totals:totals[key]+=result[key]
        for name in result['coverage']:coverage[name]=coverage.get(name,0)+1
        digest.update(json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n')
    source_digest=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {'schema_version':1,'model_version':MODEL_VERSION,'profile':'current_target_bound_abstract_contract',
        'proposed_unbound_model_excluded':True,'configuration':asdict(config),'source_sha256':source_digest,'python_version':sys.version.split()[0],'prng':'Python random.Random MT19937',
        'completed_seeds':completed,'status':'failed' if failure else 'abstract_campaign_completed',
        'gate_c_qualified':False,'native_crypto_exercised':False,'production_activation_authorized':False,
        'assumptions':ASSUMPTIONS,'native_uncovered_cases':UNCOVERED_NATIVE,'coverage_seed_counts':coverage,
        'totals':totals,'result_stream_sha256':digest.hexdigest(),'failure':failure,
        'interpretation':'Seed count is not a correctness proof. Completion covers only these abstract contracts under the stated fairness and retention assumptions.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--first-seed',type=int,default=0);parser.add_argument('--seeds',type=int,default=10000)
    parser.add_argument('--max-events-per-seed',type=int,default=2000);parser.add_argument('--max-network-queue',type=int,default=4096)
    parser.add_argument('--trace-limit',type=int,default=256);parser.add_argument('--retention-heights',type=int,default=64)
    parser.add_argument('--block-count',type=int,default=18)
    parser.add_argument('--output',type=Path,required=True,help='create-new bounded JSON evidence path')
    args=parser.parse_args();config=CampaignConfig(**{key:getattr(args,key) for key in CampaignConfig.__dataclass_fields__})
    report=run_campaign(config);encoded=json.dumps(report,sort_keys=True,indent=2).encode()+b'\n'
    if len(encoded)>1024*1024:raise Rejected('campaign artifact exceeds 1 MiB bound')
    import os
    if not args.output.is_absolute() or not args.output.parent.is_dir() or args.output.exists():raise Rejected('explicit new artifact path required')
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as output:output.write(encoded);output.flush();os.fsync(output.fileno())
    return 1 if report['failure'] else 0


if __name__=='__main__':raise SystemExit(main())
