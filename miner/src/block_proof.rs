//! Block validity proofs: segments proven in parallel and aggregated.
//!
//! A block's proof is a list of segment proofs (see [`crate::block_air`]),
//! each with its public boundary values. The verifier checks that the
//! segments chain, that the chain starts at the block's previous root, the
//! initial sponge states and first output position, that it ends at the new
//! root and at the sponge states of the block's own input and output lists,
//! that the summed input amounts plus the subsidy equal the summed output
//! amounts as integers, and that every segment's STARK proof verifies.
//!
//! Today the chaining check is done by the node; the segment interface is
//! what a recursive aggregator will consume later.
//!
//! Encoding: `u32 count`, then per segment the 92 public values followed by
//! a length-prefixed STARK proof.

use crate::block::Body;
use crate::block_air::{
    BlockAir, Carry, LIMBS, NUM_PUBLIC, SegmentPublic, SegmentWitness, initial_inputs_state, initial_outputs_state,
    inputs_state, outputs_state,
};
use crate::chain::{BlockStatement, ProofVerifier};
use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::poseidon2::Fp;
use crate::stark::{self, StarkConfig};

/// Transcript domain separator for segment proofs.
pub(crate) const DOM_SEGMENT_PROOF: u32 = 0x30;

pub(crate) fn transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_SEGMENT_PROOF));
    c
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

/// Proves every segment, one thread per segment, and encodes the aggregate.
pub fn prove_block(config: &StarkConfig, segments: &[SegmentWitness]) -> Vec<u8> {
    let proofs: Vec<SegmentProof> = std::thread::scope(|s| {
        let handles: Vec<_> = segments.iter().map(|w| s.spawn(move || prove_segment(config, w))).collect();
        handles.into_iter().map(|h| h.join().expect("segment prover panicked")).collect()
    });
    encode(&proofs)
}

pub fn encode(proofs: &[SegmentProof]) -> Vec<u8> {
    let mut w = Writer::with_capacity(proofs.len() << 18);
    w.u32(proofs.len() as u32);
    for sp in proofs {
        w.fps(&sp.public.to_values());
        let bytes = sp.proof.to_bytes();
        w.u32(bytes.len() as u32);
        w.0.extend_from_slice(&bytes);
    }
    w.finish()
}

pub fn decode(bytes: &[u8]) -> Option<Vec<SegmentProof>> {
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
    if !r.is_empty() {
        return None;
    }
    Some(out)
}

/// Assembles a block body from the segments and the encoded proof.
pub fn body_from_segments(segments: &[SegmentWitness], proof: Vec<u8>) -> Body {
    Body {
        inputs: segments.iter().flat_map(|s| s.positions()).collect(),
        outputs: segments.iter().flat_map(|s| s.commitments()).collect(),
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
    Unbalanced,
    SegmentRejected {
        index: usize,
    },
}

/// Checks the aggregate's chaining and balance against the statement,
/// without verifying the STARK proofs.
pub fn check_chaining(s: &BlockStatement<'_>, proofs: &[SegmentProof]) -> Result<(), AggregateError> {
    let first = proofs.first().ok_or(AggregateError::NoSegments)?;
    if first.public.root_in != s.prev_state_root
        || first.public.isp_in != initial_inputs_state()
        || first.public.osp_in != initial_outputs_state()
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
            || a.pos_out != b.pos_in
            || a.carry_out != b.carry_in
        {
            return Err(AggregateError::BrokenChain { index: i + 1 });
        }
    }
    let last = &proofs.last().unwrap().public;
    let expected_pos = s.first_output_position + s.body.outputs.len() as u64;
    if last.root_out != s.new_state_root
        || last.isp_out != inputs_state(&s.body.inputs)
        || last.osp_out != outputs_state(&s.body.outputs)
        || last.pos_out != expected_pos
        || last.carry_out != Carry::CLOSED
    {
        return Err(AggregateError::WrongEnd);
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
    let proofs = decode(proof).ok_or(AggregateError::Malformed)?;
    check_chaining(s, &proofs)?;
    for (i, sp) in proofs.iter().enumerate() {
        if stark::verify(config, &BlockAir, &sp.public.to_values(), &sp.proof, &mut transcript()).is_err() {
            return Err(AggregateError::SegmentRejected { index: i });
        }
    }
    Ok(())
}

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
            genesis_target: U256([0, 0, 0, 1 << 48]),
            max_target: ChainParams::MAINNET.max_target,
            max_block_size: 16 << 20,
            max_future_drift: 7200,
            median_time_window: 11,
            initial_subsidy: 50,
            halving_interval: 1000,
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
        assert_eq!(verify_block(&STARK, &st, &encode(&[])), Err(AggregateError::NoSegments));
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
                Output::new(&a.public_key(), 100).commitment,
                Output::new(&bk.public_key(), 40).commitment,
                Output::new(&d.public_key(), 7).commitment,
            ],
            proof: vec![],
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
        let tx =
            UnsignedTransaction::new(vec![(a.public_key(), 100), (bk.public_key(), 40)], vec![Output::new(&c, 130)])
                .sign(|i, _, m| if i == 0 { a.sign(m) } else { bk.sign(m) })
                .unwrap();
        let tx_d = UnsignedTransaction::new(vec![(d.public_key(), 7)], vec![Output::new(&d.public_key(), 7)])
            .sign_with(&mut d)
            .unwrap();
        let reward =
            UnsignedTransaction::new(vec![], vec![Output::new(&miner, 60)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        let txs = [tx, tx_d, reward];
        let segments = {
            let mut wtxn = chain.env().write_txn().unwrap();
            let s = SegmentWitness::collect(chain.utxo(), &mut wtxn, &txs, 2).unwrap();
            wtxn.abort();
            s
        };
        assert_eq!(segments.len(), 2);
        let t = std::time::Instant::now();
        let proof = prove_block(&STARK, &segments);
        println!("2 segments in parallel: {} bytes in {:?}", proof.len(), t.elapsed());
        let decoded = decode(&proof).unwrap();
        assert_eq!(decoded.len(), 2);
        let body = body_from_segments(&segments, proof);
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
        let proofs = decode(&body1.proof).unwrap();
        let st = BlockStatement {
            height: 1,
            prev_state_root: genesis_root,
            new_state_root: block.header.state_root,
            first_output_position: 3,
            subsidy: 50,
            body: &body1,
        };
        assert_eq!(check_chaining(&st, &proofs), Ok(()));
        let swapped = vec![proofs[1].clone(), proofs[0].clone()];
        assert_eq!(check_chaining(&st, &swapped), Err(AggregateError::BrokenChain { index: 0 }));
        assert_eq!(check_chaining(&st, &proofs[..1]), Err(AggregateError::WrongEnd));
        let mut poor = st.clone();
        poor.subsidy = 49;
        assert_eq!(check_chaining(&poor, &proofs), Err(AggregateError::Unbalanced));
        let mut moved = st.clone();
        moved.first_output_position = 4;
        assert_eq!(check_chaining(&moved, &proofs), Err(AggregateError::BrokenChain { index: 0 }));
        // A segment proof swapped for another segment's: chaining passes,
        // the STARK check fails on that index.
        let mut cross = proofs.clone();
        cross[1].proof = proofs[0].proof.clone();
        assert_eq!(verify_block(&STARK, &st, &encode(&cross)), Err(AggregateError::SegmentRejected { index: 1 }));

        // Block 2 with a stale proof is rejected by the chain; a fresh one applies.
        let reward2 =
            UnsignedTransaction::new(vec![], vec![Output::new(&miner, 50)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        let seg2 = {
            let mut wtxn = chain.env().write_txn().unwrap();
            let s = SegmentWitness::collect(chain.utxo(), &mut wtxn, &[reward2], 2).unwrap();
            wtxn.abort();
            s
        };
        let stale = body_from_segments(&seg2, block.body.proof.clone());
        let h2 = mine(&stale, GENESIS_TIME + 1200);
        assert!(matches!(
            chain.apply_block(&Block { header: h2, body: stale }, GENESIS_TIME + 1300),
            Err(ChainError::BadProof)
        ));
        let good = body_from_segments(&seg2, prove_block(&STARK, &seg2));
        let h2 = mine(&good, GENESIS_TIME + 1200);
        chain.apply_block(&Block { header: h2, body: good }, GENESIS_TIME + 1300).unwrap();
        assert_eq!(chain.tip().unwrap().unwrap().height, 2);
    }
}
