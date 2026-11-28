//! Deterministic candidate scheduling (PoSy v0.5 pp42,70–71).
//! This does not authenticate entropy, qualification, BPC membership or authority.
//! The native formation owner must independently verify those inputs and commit
//! the recomputed result before it may authorize an actual proposal.
use super::{codec::Writer, header::framed_digest, Digest48, R1ProofError, Result};
use synergy_address::r1_public::{HashAlgorithm, Primitives};
use synergy_protocol_types::{R1NetworkRef, R1ProfileSetReference};

pub const SCHEDULE_PROFILE_NAME: &str = "POSY-SCHEDULE-R1";
pub const SCHEDULE_PROFILE_SCHEMA:&[u8]=b"POSY-SCHEDULE-R1/1;POSY-CODEC-1-LE;N=U64chain,NIC64;Context=N,ActivatedProfileRef,Activated64,SeedRef64,Registry64,U64productionEpoch,Protocol48;Input=U32count,sorted(Identity48,U128selectionScore);InputCommit=SHA3-384(Bytes(POSY/PROPOSER-INPUT/R1),U16(1),Input);Draw=SHAKE256-16(Bytes(POSY/PROPOSER-DRAW/R1),U16(1),Context,InputCommit48,Bytes(seedOutput),U64counter);ticket=U128LE;upper-rejection-limit=floor(2^128/m)*m;counter-advances-every-draw-including-reject;weighted-withoutreplacement;zero-scores-final-uniform-shuffle;maxCandidates100;maxSeed65536;maxDraws65536;no-modulo-fallback;Schedule=SHA3-384(Bytes(POSY/SCHEDULE/R1),U16(1),Context,InputCommit48,U64firstHeight,U64lastHeight,U16segmentSize10,U16segmentCount100,U32count,permutation48);epoch>=1;first=1000*(epoch-1)+1;last=1000*epoch;requires-independent-qualified-seed-BPC-and-eligibility-before-authority";
const MAX_CANDIDATES: usize = 100; // Larger pools need the separately approved fairness policy.
const MAX_DRAWS: u64 = 65536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ScheduleContext {
    pub network: R1NetworkRef,
    pub activated_profiles: R1ProfileSetReference,
    pub seed_reference: [u8; 64],
    pub registry_commitment: [u8; 64],
    pub production_epoch: u64,
    pub protocol_profile: Digest48,
}
impl R1ScheduleContext {
    fn encode(&self, w: &mut Writer) -> Result<()> {
        if self.network.chain_id == 0 || self.production_epoch == 0 {
            return Err(R1ProofError::Context);
        }
        w.u64(self.network.chain_id)?;
        w.fixed(&self.network.nic)?;
        w.profile(&self.activated_profiles.profile)?;
        w.fixed(&self.activated_profiles.commitment)?;
        w.fixed(&self.seed_reference)?;
        w.fixed(&self.registry_commitment)?;
        w.u64(self.production_epoch)?;
        w.fixed(&self.protocol_profile)
    }
    fn interval(&self) -> Result<(u64, u64)> {
        let end = self
            .production_epoch
            .checked_mul(1000)
            .ok_or(R1ProofError::Bounds)?;
        let first = self
            .production_epoch
            .checked_sub(1)
            .and_then(|e| e.checked_mul(1000))
            .and_then(|n| n.checked_add(1))
            .ok_or(R1ProofError::Bounds)?;
        Ok((first, end))
    }
}
/// Selection scores are distinct from frozen positive consensus voting weights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ProposerCandidate {
    pub identity: Digest48,
    pub selection_score: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateR1Schedule {
    context: R1ScheduleContext,
    input_commitment: Digest48,
    permutation: Vec<Digest48>,
    commitment: Digest48,
    draws: u64,
}
impl CandidateR1Schedule {
    pub fn context(&self) -> &R1ScheduleContext {
        &self.context
    }
    pub fn input_commitment(&self) -> &Digest48 {
        &self.input_commitment
    }
    pub fn permutation(&self) -> &[Digest48] {
        &self.permutation
    }
    pub fn commitment(&self) -> &Digest48 {
        &self.commitment
    }
    pub fn draws(&self) -> u64 {
        self.draws
    }
    /// Planned ordinary opportunities only. Pass recovery must independently
    /// authenticate the inherited cursor and its lease; it cannot call this
    /// function with a fabricated height to manufacture a recovery opportunity.
    pub fn planned_proposer(&self, height: u64) -> Result<&Digest48> {
        let (first, last) = self.context.interval()?;
        if !(first..=last).contains(&height) {
            return Err(R1ProofError::Header);
        }
        let segment = (height - first) / 10;
        self.permutation
            .get(segment as usize % self.permutation.len())
            .ok_or(R1ProofError::Authority)
    }
}
/// Exact integer upper-interval rejection. The special zero remainder means
/// L=2^128 and every representable ticket is permitted; no overflowing 3W/2^128.
fn below(m: u128, next: &mut impl FnMut() -> Result<u128>) -> Result<u128> {
    if m == 0 {
        return Err(R1ProofError::Bounds);
    }
    let remainder = ((u128::MAX % m) + 1) % m;
    loop {
        let x = next()?;
        if remainder == 0 || x < u128::MAX - (remainder - 1) {
            return Ok(x % m);
        }
    }
}
pub fn derive_candidate_schedule(
    context: &R1ScheduleContext,
    seed_output: &[u8],
    candidates: &[R1ProposerCandidate],
) -> Result<CandidateR1Schedule> {
    context.interval()?;
    if candidates.is_empty()
        || candidates.len() > MAX_CANDIDATES
        || seed_output.is_empty()
        || seed_output.len() > 65536
    {
        return Err(R1ProofError::Bounds);
    }
    let mut remaining = candidates.to_vec();
    remaining.sort_by_key(|c| c.identity);
    if remaining.windows(2).any(|p| p[0].identity == p[1].identity) {
        return Err(R1ProofError::Authority);
    }
    let mut input = Writer::new(8192);
    input.u32(remaining.len() as u32)?;
    for c in &remaining {
        input.fixed(&c.identity)?;
        input.u128(c.selection_score)?;
    }
    let input_commitment = framed_digest(b"POSY/PROPOSER-INPUT/R1", &input.bytes)?;
    let mut draw_frame = Writer::new(70000);
    draw_frame.variable(b"POSY/PROPOSER-DRAW/R1", 128)?;
    draw_frame.u16(1)?;
    context.encode(&mut draw_frame)?;
    draw_frame.fixed(&input_commitment)?;
    draw_frame.variable(seed_output, 65536)?;
    let base = draw_frame.bytes;
    let mut counter = 0u64;
    let mut next = || -> Result<u128> {
        if counter >= MAX_DRAWS {
            return Err(R1ProofError::Bounds);
        }
        let mut bytes = base.clone();
        bytes.extend_from_slice(&counter.to_le_bytes());
        counter += 1;
        let output = Primitives
            .hash(HashAlgorithm::Shake256 { output_bytes: 16 }, &bytes)
            .map_err(|_| R1ProofError::Profile)?;
        Ok(u128::from_le_bytes(
            output
                .as_slice()
                .try_into()
                .map_err(|_| R1ProofError::Encoding)?,
        ))
    };
    let mut permutation = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let total = remaining.iter().try_fold(0u128, |sum, c| {
            sum.checked_add(c.selection_score)
                .ok_or(R1ProofError::Bounds)
        })?;
        let index = if total == 0 {
            usize::try_from(below(remaining.len() as u128, &mut next)?)
                .map_err(|_| R1ProofError::Bounds)?
        } else {
            let ticket = below(total, &mut next)?;
            let mut cumulative = 0u128;
            let mut selected = None;
            for (i, c) in remaining.iter().enumerate() {
                cumulative = cumulative
                    .checked_add(c.selection_score)
                    .ok_or(R1ProofError::Bounds)?;
                if ticket < cumulative {
                    selected = Some(i);
                    break;
                }
            }
            selected.ok_or(R1ProofError::Authority)?
        };
        permutation.push(remaining.remove(index).identity);
    }
    let (first, last) = context.interval()?;
    let mut w = Writer::new(8192);
    context.encode(&mut w)?;
    w.fixed(&input_commitment)?;
    w.u64(first)?;
    w.u64(last)?;
    w.u16(10)?;
    w.u16(100)?;
    w.u32(permutation.len() as u32)?;
    for identity in &permutation {
        w.fixed(identity)?;
    }
    let commitment = framed_digest(b"POSY/SCHEDULE/R1", &w.bytes)?;
    Ok(CandidateR1Schedule {
        context: context.clone(),
        input_commitment,
        permutation,
        commitment,
        draws: counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> R1ScheduleContext {
        R1ScheduleContext {
            network: R1NetworkRef {
                chain_id: u64::MAX - 1,
                nic: [1; 64],
            },
            activated_profiles: R1ProfileSetReference {
                profile: synergy_protocol_types::R1ProfileRef {
                    name: "SYNTHETIC-PROFILES".into(),
                    revision: 1,
                },
                commitment: [2; 64],
            },
            seed_reference: [3; 64],
            registry_commitment: [4; 64],
            production_epoch: 1,
            protocol_profile: [5; 48],
        }
    }
    fn candidates() -> Vec<R1ProposerCandidate> {
        [7, 0, 2, 1, 0]
            .iter()
            .enumerate()
            .map(|(i, n)| R1ProposerCandidate {
                identity: [i as u8 + 1; 48],
                selection_score: *n,
            })
            .collect()
    }
    #[test]
    fn canonical_input_order_and_zero_score_final_shuffle() {
        let c = context();
        let a = derive_candidate_schedule(&c, b"PUBLIC SYNTHETIC SEED", &candidates()).unwrap();
        // Independently encoded with Python struct/hashlib SHAKE256/SHA3-384.
        assert_eq!(
            a.permutation.iter().map(|id| id[0]).collect::<Vec<_>>(),
            vec![1, 4, 3, 5, 2]
        );
        assert_eq!(a.draws, 5);
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(&a.input_commitment),"8747983d3571d0d59ab29fe470a6c08cfc799a7e87fc34d3c0ad81357b6f095111ad9ba9b0c22365270f6d2fd284dfe2");
        assert_eq!(hex(&a.commitment),"d16ad81468fd92e2cb1f24b98233deeead916aa2578453a1b6969ae060a4bbe3a3c97ab0741d89b1524c8776cb96dd5d");
        let mut reversed = candidates();
        reversed.reverse();
        assert_eq!(
            a,
            derive_candidate_schedule(&c, b"PUBLIC SYNTHETIC SEED", &reversed).unwrap()
        );
        assert_eq!(
            a.permutation
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            5
        );
        assert!(a.permutation[..3]
            .iter()
            .all(|id| [1, 3, 4].contains(&id[0])));
        assert!(a.permutation[3..].iter().all(|id| [2, 5].contains(&id[0])));
        assert_eq!(
            a.planned_proposer(1).unwrap(),
            a.planned_proposer(10).unwrap()
        );
        assert_eq!(a.planned_proposer(11).unwrap(), &a.permutation[1]);
        assert_eq!(a.planned_proposer(1000).unwrap(), &a.permutation[99 % 5]);
        assert!(a.planned_proposer(0).is_err());
        assert!(a.planned_proposer(1001).is_err());
    }
    #[test]
    fn exact_upper_rejection_and_power_two_endpoints() {
        let mut draws = vec![5, u128::MAX];
        let mut used = 0;
        assert_eq!(
            below(3, &mut || {
                used += 1;
                Ok(draws.pop().unwrap())
            })
            .unwrap(),
            2
        );
        assert_eq!(used, 2);
        assert_eq!(below(2, &mut || Ok(u128::MAX)).unwrap(), 1);
        assert_eq!(below(1, &mut || Ok(u128::MAX)).unwrap(), 0);
        assert!(below(0, &mut || panic!("must reject before drawing")).is_err());
    }
    #[test]
    fn context_score_and_seed_changes_change_schedule_commitment() {
        let expected =
            derive_candidate_schedule(&context(), b"PUBLIC SYNTHETIC SEED", &candidates()).unwrap();
        for field in 0..7 {
            let mut c = context();
            match field {
                0 => c.network.nic[63] ^= 1,
                1 => c.seed_reference[63] ^= 1,
                2 => c.registry_commitment[63] ^= 1,
                3 => c.production_epoch = 2,
                4 => c.protocol_profile[47] ^= 1,
                5 => c.activated_profiles.commitment[63] ^= 1,
                _ => c.network.chain_id -= 1,
            };
            assert_ne!(
                expected.commitment,
                derive_candidate_schedule(&c, b"PUBLIC SYNTHETIC SEED", &candidates())
                    .unwrap()
                    .commitment
            );
        }
        let mut cs = candidates();
        cs[0].selection_score += 1;
        assert_ne!(
            expected.commitment,
            derive_candidate_schedule(&context(), b"PUBLIC SYNTHETIC SEED", &cs)
                .unwrap()
                .commitment
        );
        assert_ne!(
            expected.commitment,
            derive_candidate_schedule(&context(), b"DIFFERENT SYNTHETIC SEED", &candidates())
                .unwrap()
                .commitment
        );
    }
    #[test]
    fn malformed_population_overflow_and_epoch_reject() {
        let mut cs = candidates();
        cs[0].selection_score = u128::MAX;
        assert!(derive_candidate_schedule(&context(), b"PUBLIC", &cs).is_err());
        let mut cs = candidates();
        cs[1].identity = cs[0].identity;
        assert!(derive_candidate_schedule(&context(), b"PUBLIC", &cs).is_err());
        assert!(derive_candidate_schedule(&context(), b"PUBLIC", &[]).is_err());
        let mut c = context();
        c.production_epoch = u64::MAX;
        assert!(derive_candidate_schedule(&c, b"PUBLIC", &candidates()).is_err());
    }
}
