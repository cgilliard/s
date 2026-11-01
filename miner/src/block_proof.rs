//! Block validity proofs: segments proven in parallel and aggregated.
//!
//! A block's proof is a list of transaction segment proofs (see
//! [`crate::block_air`]) and one name segment proof (see
//! [`crate::name_air`]), each with its public boundary values. The
//! verifier checks that the segments chain, that the chain starts at the
//! block's previous root, the initial sponge states and first output
//! position, that the name segment continues from where the last segment
//! ends and ends at the new root and the block's end position, that the
//! sponge states are those of the block's own input, output, operation and
//! sweep lists, that the summed input amounts plus the subsidy equal the
//! summed output amounts as integers, and that every STARK proof verifies.
//!
//! This module's checks are native; [`crate::aggregate`] does the same in
//! a recursive proof, which is what blocks carry.
//!
//! Encoding: `u32 count`, then per segment its public values followed by a
//! length-prefixed STARK proof, then the name segment's the same way.

use crate::block::Body;
use crate::block_air::{
    BlockAir, Carry, LIMBS, NUM_PUBLIC, SegmentPublic, SegmentWitness, initial_inputs_state, initial_names_state,
    initial_outputs_state, inputs_state, names_state, outputs_state, sweeps_state,
};
use crate::chain::{BlockStatement, ProofVerifier};
use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::name_air::{NAME_LOG_ROWS, NUM_PUBLIC as NAME_PUBLIC, NameAir, NamePublic, NameWitness};
use crate::names::{OpKind, count_ops};
use crate::poseidon2::Fp;
use crate::stark::{self, StarkConfig};

/// Transcript domain separator for segment proofs.
pub(crate) const DOM_SEGMENT_PROOF: u32 = 0x30;
/// Transcript domain separator for name segment proofs.
pub(crate) const DOM_NAME_PROOF: u32 = 0x34;

pub(crate) fn transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_SEGMENT_PROOF));
    c
}

pub(crate) fn name_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_NAME_PROOF));
    c
}

/// A proven name segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameProof {
    pub public: NamePublic,
    pub proof: stark::Proof,
}

/// Proves a block's name segment padded to `2^log_n` rows.
pub fn prove_name_padded(config: &StarkConfig, witness: &NameWitness, log_n: usize) -> NameProof {
    let (trace, public) = NameAir::generate_trace_padded(witness, log_n);
    let proof = stark::prove(config, &NameAir, &trace, &public.to_values(), &mut name_transcript());
    NameProof { public, proof }
}

/// A proven segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentProof {
    pub public: SegmentPublic,
    pub proof: stark::Proof,
}

/// Proves one segment at its natural height.
pub fn prove_segment(config: &StarkConfig, witness: &SegmentWitness) -> SegmentProof {
    let (trace, public) = BlockAir::generate_trace(witness);
    let proof = stark::prove(config, &BlockAir, &trace, &public.to_values(), &mut transcript());
    SegmentProof { public, proof }
}

/// Proves one segment padded to `2^log_n` rows, the shape the aggregator
/// expects.
pub fn prove_segment_padded(config: &StarkConfig, witness: &SegmentWitness, log_n: usize) -> SegmentProof {
    let (trace, public) = BlockAir::generate_trace_padded(witness, log_n);
    let proof = stark::prove(config, &BlockAir, &trace, &public.to_values(), &mut transcript());
    SegmentProof { public, proof }
}

/// Proves every segment and the name segment (at its natural height),
/// one thread each, and encodes the lot.
pub fn prove_block(config: &StarkConfig, segments: &[SegmentWitness], name: &NameWitness) -> Vec<u8> {
    let (proofs, name_proof) = std::thread::scope(|s| {
        let handles: Vec<_> = segments.iter().map(|w| s.spawn(move || prove_segment(config, w))).collect();
        let np = s.spawn(move || {
            let (trace, public) = NameAir::generate_trace(name);
            let proof = stark::prove(config, &NameAir, &trace, &public.to_values(), &mut name_transcript());
            NameProof { public, proof }
        });
        let proofs: Vec<SegmentProof> =
            handles.into_iter().map(|h| h.join().expect("segment prover panicked")).collect();
        (proofs, np.join().expect("name segment prover panicked"))
    });
    encode(&proofs, &name_proof)
}

pub fn encode(proofs: &[SegmentProof], name: &NameProof) -> Vec<u8> {
    let mut w = Writer::with_capacity((proofs.len() + 1) << 18);
    w.u32(proofs.len() as u32);
    for sp in proofs {
        w.fps(&sp.public.to_values());
        let bytes = sp.proof.to_bytes();
        w.u32(bytes.len() as u32);
        w.0.extend_from_slice(&bytes);
    }
    w.fps(&name.public.to_values());
    let bytes = name.proof.to_bytes();
    w.u32(bytes.len() as u32);
    w.0.extend_from_slice(&bytes);
    w.finish()
}

pub fn decode(bytes: &[u8]) -> Option<(Vec<SegmentProof>, NameProof)> {
    let mut r = Reader(bytes);
    let n = r.len(NUM_PUBLIC * 4)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut values = Vec::with_capacity(NUM_PUBLIC);
        for _ in 0..NUM_PUBLIC {
            values.push(r.fp()?);
        }
        let public = SegmentPublic::from_values(&values)?;
        let len = r.len(1)?;
        let proof = stark::Proof::from_bytes(r.take(len)?)?;
        out.push(SegmentProof { public, proof });
    }
    let mut values = Vec::with_capacity(NAME_PUBLIC);
    for _ in 0..NAME_PUBLIC {
        values.push(r.fp()?);
    }
    let public = NamePublic::from_values(&values)?;
    let len = r.len(1)?;
    let proof = stark::Proof::from_bytes(r.take(len)?)?;
    if !r.is_empty() {
        return None;
    }
    Some((out, NameProof { public, proof }))
}

/// Assembles a block body from the segments, the name witness and the
/// encoded proof.
pub fn body_from_segments(segments: &[SegmentWitness], name: &NameWitness, proof: Vec<u8>) -> Body {
    Body {
        inputs: segments.iter().flat_map(|s| s.positions()).collect(),
        outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
        ops: name.block_ops(),
        sweeps: name.sweeps(),
        proof,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateError {
    Malformed,
    NoSegments,
    /// Segment `index` does not start where the previous one ended (or, for
    /// the first, where the block starts).
    BrokenChain {
        index: usize,
    },
    /// The last segment does not end at the block's root, lists or position.
    WrongEnd,
    /// The name segment does not continue from the last segment, or does
    /// not end at the block's root, position, operation and sweep lists,
    /// height or caps.
    WrongNames,
    Unbalanced,
    SegmentRejected {
        index: usize,
    },
    NameSegmentRejected,
}

/// Checks the aggregate's chaining and balance against the statement,
/// without verifying the STARK proofs.
pub fn check_chaining(s: &BlockStatement<'_>, proofs: &[SegmentProof], name: &NameProof) -> Result<(), AggregateError> {
    let first = proofs.first().ok_or(AggregateError::NoSegments)?;
    if first.public.root_in != s.prev_state_root
        || first.public.isp_in != initial_inputs_state()
        || first.public.osp_in != initial_outputs_state()
        || first.public.nsp_in != initial_names_state()
        || first.public.pos_in != s.first_output_position
        || first.public.carry_in != Carry::CLOSED
    {
        return Err(AggregateError::BrokenChain { index: 0 });
    }
    for (i, pair) in proofs.windows(2).enumerate() {
        let (a, b) = (&pair[0].public, &pair[1].public);
        if a.root_out != b.root_in
            || a.isp_out != b.isp_in
            || a.osp_out != b.osp_in
            || a.nsp_out != b.nsp_in
            || a.pos_out != b.pos_in
            || a.carry_out != b.carry_in
        {
            return Err(AggregateError::BrokenChain { index: i + 1 });
        }
    }
    let last = &proofs.last().unwrap().public;
    let after_outputs = s.first_output_position + s.body.outputs.len() as u64;
    if last.isp_out != inputs_state(&s.body.inputs)
        || last.osp_out != outputs_state(&s.body.outputs)
        || last.nsp_out != names_state(&s.body.op_digests())
        || last.pos_out != after_outputs
        || last.carry_out != Carry::CLOSED
    {
        return Err(AggregateError::WrongEnd);
    }
    let nm = &name.public;
    let kinds = s.body.ops.iter().map(|o| o.kind()).chain(s.body.sweeps.iter().map(|_| OpKind::Sweep));
    let counts = count_ops(kinds).map_err(|_| AggregateError::WrongNames)?;
    if nm.root_in != last.root_out
        || nm.root_out != s.new_state_root
        || nm.pos_in != last.pos_out
        || nm.pos_out != after_outputs + s.body.commit_positions(0).len() as u64
        || nm.nsp != last.nsp_out
        || nm.ssp != sweeps_state(&s.body.sweeps)
        || nm.height != s.height
        || nm.counts.iter().zip(&counts).any(|(a, b)| *a as usize != *b)
    {
        return Err(AggregateError::WrongNames);
    }
    let total_in: u128 = proofs.iter().map(|p| SegmentPublic::total(&p.public.sum_in)).sum();
    let total_out: u128 = proofs.iter().map(|p| SegmentPublic::total(&p.public.sum_out)).sum();
    if total_in + s.subsidy as u128 != total_out {
        return Err(AggregateError::Unbalanced);
    }
    Ok(())
}

/// Full verification of an encoded block proof against a statement.
pub fn verify_block(config: &StarkConfig, s: &BlockStatement<'_>, proof: &[u8]) -> Result<(), AggregateError> {
    let (proofs, name) = decode(proof).ok_or(AggregateError::Malformed)?;
    check_chaining(s, &proofs, &name)?;
    for (i, sp) in proofs.iter().enumerate() {
        if stark::verify(config, &BlockAir, &sp.public.to_values(), &sp.proof, &mut transcript()).is_err() {
            return Err(AggregateError::SegmentRejected { index: i });
        }
    }
    if stark::verify(config, &NameAir, &name.public.to_values(), &name.proof, &mut name_transcript()).is_err() {
        return Err(AggregateError::NameSegmentRejected);
    }
    Ok(())
}

/// The rows every name segment is padded to on mainnet.
pub const NAME_ROWS_LOG: usize = NAME_LOG_ROWS;

/// Verifies block proofs with the STARK verifier.
#[derive(Clone, Copy, Debug)]
pub struct StarkVerifier {
    pub config: StarkConfig,
}

impl ProofVerifier for StarkVerifier {
    fn verify(&self, s: &BlockStatement<'_>, proof: &[u8]) -> bool {
        verify_block(&self.config, s, proof).is_ok()
    }
}

/// Limb count re-export for callers computing totals.
pub const AMOUNT_LIMBS: usize = LIMBS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, Header};
    use crate::chain::{Chain, ChainError, ChainParams};
    use crate::difficulty::U256;
    use crate::pow::{self, Dataset, PowParams, SeedText, nonce_from_u64};
    use crate::state_tree::EMPTY;
    use crate::transaction::{Key, Output, Sig, UnsignedTransaction};
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-block-proof-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const POW: PowParams = PowParams { log_dataset_items: 8, parents: 32, accesses: 64 };
    const GENESIS_TIME: u64 = 1_700_000_000;
    /// Segment proofs in these tests, verified directly by the node.
    const STARK: StarkConfig = StarkConfig { log_blowup: 1, num_queries: 20, pow_bits: 0, zk: false, commit_bits: 0 };

    fn params() -> ChainParams {
        ChainParams {
            pow: POW,
            genesis_timestamp: 0,
            genesis_nonce: [0u8; 32],
            genesis_target: U256([0, 0, 0, 1 << 48]),
            max_target: ChainParams::MAINNET.max_target,
            max_block_size: 16 << 20,
            max_future_drift: 7200,
            median_time_window: 11,
            emission: &[(1000, 50)],
            aggregator: crate::aggregate::AggregatorParams::MAINNET,
        }
    }

    fn seed() -> SeedText {
        let text: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 253) as u8).collect();
        SeedText::from_bytes(POW, text)
    }

    fn key(tag: u8) -> Key {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s)
    }

    #[test]
    fn verifier_rejects_garbage() {
        let v = StarkVerifier { config: STARK };
        let body = Body::default();
        let st = BlockStatement {
            height: 1,
            prev_state_root: EMPTY,
            new_state_root: EMPTY,
            first_output_position: 0,
            subsidy: 50,
            body: &body,
        };
        assert!(!v.verify(&st, &[]));
        assert!(!v.verify(&st, &[1, 2, 3]));
        let empty = NameWitness { root_in: EMPTY, pos_in: 0, height: 1, ops: vec![] };
        let name = prove_name_padded(&STARK, &empty, 4);
        assert_eq!(verify_block(&STARK, &st, &encode(&[], &name)), Err(AggregateError::NoSegments));
    }

    /// A policy output (2-of-3 multisig) made in one proven block is spent
    /// in the next through the pool, the proof and the chain.
    #[test]
    #[ignore = "proves blocks; run with --release"]
    fn policy_spend_block_proves_and_applies() {
        use crate::mempool::{Mempool, Policy as PoolPolicy};
        use crate::policy::{Cond, CondWitness, Leaf, Mode, Policy, Signer};
        use crate::poseidon2::DIGEST;
        use crate::transaction::{Transaction, pubkey_hash};
        use crate::xmss::Digest;
        let dir = TempDir::new("e2e-policy");
        let p = params();
        let seed = seed();
        let dataset = Dataset::generate(&seed);
        let chain = Chain::open(&dir.0, 64 << 20, p, seed, StarkVerifier { config: STARK }).unwrap();
        let mut a = key(1);
        let mut bk = key(2);
        let c = key(3);
        let miner = key(4).public_key();
        let keys: Vec<Digest> = [&a, &bk, &c].iter().map(|k| pubkey_hash(&k.public_key())).collect();
        let multisig = Policy::new(vec![Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys }])]);
        let genesis_body = Body {
            inputs: vec![],
            outputs: vec![Output::new(&a.public_key(), 100).block_output()],
            proof: vec![],
            ..Default::default()
        };
        let genesis_root = chain.preview_state_root(&genesis_body).unwrap();
        let genesis = Block {
            header: Header {
                prev_hash: EMPTY,
                height: 0,
                timestamp: GENESIS_TIME,
                body_commitment: genesis_body.commitment(),
                state_root: genesis_root,
                mix: EMPTY,
                nonce: [0u8; 32],
            },
            body: genesis_body,
        };
        chain.init_genesis(&genesis).unwrap();
        let names_for = |segments: &[SegmentWitness], height: u32, wtxn: &heed::RwTxn| {
            NameWitness {
                root_in: chain.utxo().root(wtxn).unwrap(),
                pos_in: chain.utxo().next_position(wtxn).unwrap(),
                height,
                ops: vec![],
            }
            .with_segments(segments)
        };
        let mine = |body: &Body, timestamp: u64| -> Header {
            let mut header = chain.template(body, timestamp).unwrap();
            let tip = chain.tip().unwrap().unwrap();
            let target = chain.expected_target(&tip).unwrap();
            let (nonce, out) =
                pow::mine(&dataset, &header.pow_hash(), &target, (0..1_000_000).map(nonce_from_u64)).unwrap();
            header.nonce = nonce;
            header.mix = out.mix;
            header
        };
        let prove_and_apply = |txs: &[Transaction], height: u32, time: u64| {
            let (segments, names) = {
                let mut wtxn = chain.env().write_txn().unwrap();
                let s = SegmentWitness::collect(chain.utxo(), &mut wtxn, txs, 4, height).unwrap();
                let n = names_for(&s, height, &wtxn);
                wtxn.abort();
                (s, n)
            };
            let proof = prove_block(&STARK, &segments, &names);
            let body = body_from_segments(&segments, &names, proof);
            let header = mine(&body, time);
            chain.apply_block(&Block { header, body }, time + 100).unwrap();
            assert_eq!(chain.tip().unwrap().unwrap().height, height);
        };

        // Block 1: A pays 90 into the multisig, fee 10; the miner takes 60.
        let funding = multisig.output(90, [Fp::new(7); DIGEST]);
        let mut tx1 = UnsignedTransaction::new(vec![(a.public_key(), 100)], vec![funding]).sign_with(&mut a).unwrap();
        tx1.set_positions(&[0]);
        let reward1 =
            UnsignedTransaction::new(vec![], vec![Output::new(&miner, 60)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        prove_and_apply(&[tx1, reward1], 1, GENESIS_TIME + 600);
        // The funding output sits at position 1, created at height 1.
        {
            let rtxn = chain.env().read_txn().unwrap();
            let (c1, _, created) = chain.utxo().output_at(&rtxn, 1).unwrap().unwrap();
            assert_eq!(c1, funding.commitment);
            assert_eq!(created, 1);
        }

        // Block 2: A and B spend the multisig to C, fee 10, through the pool.
        let mut spend = multisig.spend(0, 90, 1);
        let outputs = vec![Output::new(&c.public_key(), 80)];
        let body =
            UnsignedTransaction::new(vec![], outputs.clone()).with_policy_inputs(vec![spend.clone()]).body_hash();
        spend.witness[0] = CondWitness::Signatures(vec![
            Signer { key: 0, pubkey: a.public_key(), signature: a.sign(&body).unwrap() },
            Signer { key: 1, pubkey: bk.public_key(), signature: bk.sign(&body).unwrap() },
        ]);
        let tx2 = UnsignedTransaction::new(vec![], outputs)
            .with_policy_inputs(vec![spend])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap();
        assert_eq!(tx2.weight(), 2);
        let mut pool = Mempool::with_policy(1 << 20, PoolPolicy::NONE);
        {
            let rtxn = chain.env().read_txn().unwrap();
            pool.insert(tx2.clone(), chain.utxo(), chain.names(), &rtxn, 2).unwrap();
            // The same output again is a conflict; a wrong state number is a
            // policy rejection only if the leaf cares, so tamper the amount.
            let mut bad = tx2.clone();
            bad.policy_inputs[0].amount = 91;
            assert!(matches!(
                pool.insert(bad, chain.utxo(), chain.names(), &rtxn, 2),
                Err(crate::mempool::Reject::UnknownInput(_))
            ));
        }
        let reward2 =
            UnsignedTransaction::new(vec![], vec![Output::new(&miner, 60)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        prove_and_apply(&[tx2, reward2], 2, GENESIS_TIME + 1200);
        {
            let rtxn = chain.env().read_txn().unwrap();
            assert!(chain.utxo().output_at(&rtxn, 1).unwrap().is_none(), "the multisig output is spent");
            assert!(chain.utxo().output_at(&rtxn, 3).unwrap().is_some(), "C's output exists");
        }
    }

    #[test]
    #[ignore = "proves blocks; run with --release"]
    fn mine_prove_and_apply_segmented_block() {
        let dir = TempDir::new("e2e");
        let p = params();
        let seed = seed();
        let dataset = Dataset::generate(&seed);
        let chain = Chain::open(&dir.0, 64 << 20, p, seed, StarkVerifier { config: STARK }).unwrap();

        // Genesis pays A, B and D.
        let mut a = key(1);
        let mut bk = key(2);
        let c = key(3).public_key();
        let miner = key(4).public_key();
        let mut d = key(5);
        let genesis_body = Body {
            inputs: vec![],
            outputs: vec![
                Output::new(&a.public_key(), 100).block_output(),
                Output::new(&bk.public_key(), 40).block_output(),
                Output::new(&d.public_key(), 7).block_output(),
            ],
            proof: vec![],
            ..Default::default()
        };
        let genesis_root = chain.preview_state_root(&genesis_body).unwrap();
        let genesis = Block {
            header: Header {
                prev_hash: EMPTY,
                height: 0,
                timestamp: GENESIS_TIME,
                body_commitment: genesis_body.commitment(),
                state_root: genesis_root,
                mix: EMPTY,
                nonce: [0u8; 32],
            },
            body: genesis_body,
        };
        chain.init_genesis(&genesis).unwrap();

        // Block 1, three transactions in two segments: A and B pay C with a
        // fee of 10; D pays itself; the miner claims subsidy 50 plus fee 10.
        let mut tx =
            UnsignedTransaction::new(vec![(a.public_key(), 100), (bk.public_key(), 40)], vec![Output::new(&c, 130)])
                .sign(|i, _, m| if i == 0 { a.sign(m) } else { bk.sign(m) })
                .unwrap();
        tx.set_positions(&[0, 1]);
        let mut tx_d = UnsignedTransaction::new(vec![(d.public_key(), 7)], vec![Output::new(&d.public_key(), 7)])
            .sign_with(&mut d)
            .unwrap();
        tx_d.set_positions(&[2]);
        let reward =
            UnsignedTransaction::new(vec![], vec![Output::new(&miner, 60)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        let txs = [tx, tx_d, reward];
        let empty_names = |segments: &[SegmentWitness], height: u32, wtxn: &heed::RwTxn| {
            NameWitness {
                root_in: chain.utxo().root(wtxn).unwrap(),
                pos_in: chain.utxo().next_position(wtxn).unwrap(),
                height,
                ops: vec![],
            }
            .with_segments(segments)
        };
        let (segments, names) = {
            let mut wtxn = chain.env().write_txn().unwrap();
            let s = SegmentWitness::collect(chain.utxo(), &mut wtxn, &txs, 2, 1).unwrap();
            let n = empty_names(&s, 1, &wtxn);
            wtxn.abort();
            (s, n)
        };
        assert_eq!(segments.len(), 2);
        let t = std::time::Instant::now();
        let proof = prove_block(&STARK, &segments, &names);
        println!("2 segments and the name segment in parallel: {} bytes in {:?}", proof.len(), t.elapsed());
        let (decoded, _) = decode(&proof).unwrap();
        assert_eq!(decoded.len(), 2);
        let body = body_from_segments(&segments, &names, proof);
        assert_eq!(body.inputs, vec![0, 1, 2]);
        assert_eq!(body.outputs.len(), 3);

        let mine = |body: &Body, timestamp: u64| -> Header {
            let mut header = chain.template(body, timestamp).unwrap();
            let tip = chain.tip().unwrap().unwrap();
            let target = chain.expected_target(&tip).unwrap();
            let (nonce, out) =
                pow::mine(&dataset, &header.pow_hash(), &target, (0..1_000_000).map(nonce_from_u64)).unwrap();
            header.nonce = nonce;
            header.mix = out.mix;
            header
        };
        let header = mine(&body, GENESIS_TIME + 600);
        assert_eq!(header.state_root, decoded[1].public.root_out);
        let block = Block { header, body };
        let t = std::time::Instant::now();
        chain.apply_block(&block, GENESIS_TIME + 700).unwrap();
        println!("apply (incl. verify of both segments): {:?}", t.elapsed());
        assert_eq!(chain.tip().unwrap().unwrap().height, 1);

        // Aggregate-level failures against the real statement.
        let statement = |body: &Body| {
            let tip = chain.tip().unwrap().unwrap();
            (tip, body.clone())
        };
        let (_, body1) = statement(&block.body);
        let (proofs, name) = decode(&body1.proof).unwrap();
        let st = BlockStatement {
            height: 1,
            prev_state_root: genesis_root,
            new_state_root: block.header.state_root,
            first_output_position: 3,
            subsidy: 50,
            body: &body1,
        };
        assert_eq!(check_chaining(&st, &proofs, &name), Ok(()));
        let swapped = vec![proofs[1].clone(), proofs[0].clone()];
        assert_eq!(check_chaining(&st, &swapped, &name), Err(AggregateError::BrokenChain { index: 0 }));
        assert_eq!(check_chaining(&st, &proofs[..1], &name), Err(AggregateError::WrongEnd));
        let mut poor = st.clone();
        poor.subsidy = 49;
        assert_eq!(check_chaining(&poor, &proofs, &name), Err(AggregateError::Unbalanced));
        let mut moved = st.clone();
        moved.first_output_position = 4;
        assert_eq!(check_chaining(&moved, &proofs, &name), Err(AggregateError::BrokenChain { index: 0 }));
        let mut other = name.clone();
        other.public.height += 1;
        assert_eq!(check_chaining(&st, &proofs, &other), Err(AggregateError::WrongNames));
        // A segment proof swapped for another segment's: chaining passes,
        // the STARK check fails on that index; a name proof for other
        // public values fails its check.
        let mut cross = proofs.clone();
        cross[1].proof = proofs[0].proof.clone();
        assert_eq!(
            verify_block(&STARK, &st, &encode(&cross, &name)),
            Err(AggregateError::SegmentRejected { index: 1 })
        );
        let mut forged = name.clone();
        forged.proof = proofs[0].proof.clone();
        assert_eq!(verify_block(&STARK, &st, &encode(&proofs, &forged)), Err(AggregateError::NameSegmentRejected));

        // Block 2 with a stale proof is rejected by the chain; a fresh one applies.
        let reward2 =
            UnsignedTransaction::new(vec![], vec![Output::new(&miner, 50)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        let (seg2, names2) = {
            let mut wtxn = chain.env().write_txn().unwrap();
            let s = SegmentWitness::collect(chain.utxo(), &mut wtxn, &[reward2], 2, 2).unwrap();
            let n = empty_names(&s, 2, &wtxn);
            wtxn.abort();
            (s, n)
        };
        let stale = body_from_segments(&seg2, &names2, block.body.proof.clone());
        let h2 = mine(&stale, GENESIS_TIME + 1200);
        assert!(matches!(
            chain.apply_block(&Block { header: h2, body: stale }, GENESIS_TIME + 1300),
            Err(ChainError::BadProof)
        ));
        let good = body_from_segments(&seg2, &names2, prove_block(&STARK, &seg2, &names2));
        let h2 = mine(&good, GENESIS_TIME + 1200);
        chain.apply_block(&Block { header: h2, body: good }, GENESIS_TIME + 1300).unwrap();
        assert_eq!(chain.tip().unwrap().unwrap().height, 2);
    }
}
