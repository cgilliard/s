//! `tabminer`: runs a single-node chain on mainnet consensus parameters,
//! mining and proving every block locally.
//!
//! ```text
//! tabminer [mine] [--data DIR] [--blocks N] [--txs N] [--jobs N]
//! tabminer show [--data DIR]
//! ```
//!
//! With no command, `tabminer` mines. The data directory defaults to
//! `~/.tabernacle/tabminer` (`./tabminer-data` when `HOME` is unset).
//!
//! `mine` creates the chain (an empty genesis block at the current time)
//! and a development wallet on first use, then builds blocks on the tip:
//! a coinbase paying the subsidy to the wallet, plus up to `--txs`
//! transfers, each splitting one of the wallet's outputs in two. The UTXO
//! set roughly doubles per block until the transfers fill the 16
//! segments a block allows. Each block is proven (segments, then the
//! aggregation tree), mined, and applied through full validation,
//! including the proof. `--blocks 0` (the default) runs until interrupted.
//! `--jobs` bounds how many segments are proven at once.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tabminer::aggregate::{AggregateVerifier, Progress, Statement, prove_block_with};
use tabminer::block::{Block, Body, Header};
use tabminer::block_air::{ROWS_PER_INPUT, ROWS_PER_OUTPUT, SegmentWitness};
use tabminer::chain::{BlockStatement, Chain, ChainParams};
use tabminer::poseidon2::digest_to_bytes;
use tabminer::pow::{Dataset, Digest, Nonce, PowOutput, SeedText, Target, hashimoto, nonce_from_u64};
use tabminer::state_tree::EMPTY;
use tabminer::transaction::{Sig, Transaction, UnsignedTransaction};
use tabminer::wallet::Wallet;

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage:
  tabminer [mine] [--data DIR] [--blocks N] [--txs N] [--jobs N]
  tabminer show [--data DIR]

  --data DIR   chain and wallet directory (default ~/.tabernacle/tabminer)
  --blocks N   blocks to mine, 0 for no limit (default 0)
  --txs N      most transfers per block (default 1000: as many as fit)
  --jobs N     segments proven at once (default 2)";

/// LMDB map size: an upper bound on the database, reserved as address space.
const MAP_SIZE: usize = 4 << 30;

struct Args {
    command: String,
    data: PathBuf,
    blocks: u64,
    txs: usize,
    jobs: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1).peekable();
    // No command, or only options, means `mine`.
    let command = match it.peek() {
        Some(c) if !c.starts_with('-') => it.next().unwrap(),
        _ => "mine".to_string(),
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let data = home.map(|h| h.join(".tabernacle").join("tabminer")).unwrap_or_else(|| PathBuf::from("tabminer-data"));
    let mut a = Args { command, data, blocks: 0, txs: 1000, jobs: 2 };
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        let number = |v: String| v.parse::<u64>().map_err(|_| format!("{flag}: not a number: {v}"));
        match flag.as_str() {
            "--data" => a.data = PathBuf::from(value()?),
            "--blocks" => a.blocks = number(value()?)?,
            "--txs" => a.txs = number(value()?)? as usize,
            "--jobs" => a.jobs = number(value()?)?.max(1) as usize,
            "-h" | "--help" => return Err(String::new()),
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(a)
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    let result = match args.command.as_str() {
        "mine" => mine(&args),
        "show" => show(&args),
        other => {
            eprintln!("error: unknown command {other}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hex(d: &Digest) -> String {
    digest_to_bytes(d).iter().map(|b| format!("{b:02x}")).collect()
}

fn short(d: &Digest) -> String {
    hex(d)[..16].to_string()
}

fn secs(d: Duration) -> String {
    format!("{:.2}s", d.as_secs_f64())
}

/// Coins as whole units with eight decimals.
fn fmt_coins(amount: u128) -> String {
    format!("{}.{:08}", amount / 100_000_000, amount % 100_000_000)
}

/// Expected hashes to meet `target`: `2^248 / (target + 1)`, as log2.
fn work_bits(target: &Target) -> f64 {
    let t = target.0.iter().fold(0f64, |acc, b| acc * 256.0 + *b as f64);
    248.0 - (t + 1.0).log2()
}

fn open_chain(args: &Args, params: ChainParams, seed: SeedText) -> AnyResult<Chain<AggregateVerifier>> {
    std::fs::create_dir_all(args.data.join("chain"))?;
    Ok(Chain::open(&args.data.join("chain"), MAP_SIZE, params, seed, AggregateVerifier::new(params.aggregator))?)
}

fn show(args: &Args) -> AnyResult<()> {
    let params = ChainParams::MAINNET;
    let chain = open_chain(args, params, SeedText::new(params.pow))?;
    let Some(tip) = chain.tip()? else {
        println!("no chain in {}", args.data.display());
        return Ok(());
    };
    println!("{:>6}  {:16}  {:>19}  {:>6} {:>7}  {:>9}", "height", "id", "time", "inputs", "outputs", "proof");
    for h in 0..=tip.height {
        let header = chain.header_at(h)?.ok_or("missing header")?;
        let body = chain.body_by_hash(&header.hash())?.ok_or("missing body")?;
        println!(
            "{:>6}  {}  {:>19}  {:>6} {:>7}  {:>6} KB",
            h,
            short(&header.hash()),
            header.timestamp,
            body.inputs.len(),
            body.outputs.len(),
            body.proof.len() / 1000
        );
    }
    println!("tip {} at height {}, state root {}", hex(&tip.hash()), tip.height, short(&tip.state_root));
    Ok(())
}

/// Searches nonces on every thread from a time-based start until one
/// meets `target`. Returns the nonce, its output and the hashes tried.
fn solve(dataset: &Dataset, header_hash: &Digest, target: &Target) -> (Nonce, PowOutput, u64) {
    let threads = tabminer::parallel::threads() as u64;
    let start = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0) << 8;
    let found = AtomicBool::new(false);
    let tried = AtomicU64::new(0);
    let result = std::sync::Mutex::new(None);
    std::thread::scope(|s| {
        for t in 0..threads {
            let (found, tried, result) = (&found, &tried, &result);
            s.spawn(move || {
                let mut n = start.wrapping_add(t);
                let mut local = 0u64;
                while !found.load(Ordering::Relaxed) {
                    let nonce = nonce_from_u64(n);
                    let out = hashimoto(dataset, header_hash, &nonce);
                    local += 1;
                    if target.is_met_by(&out.result) && !found.swap(true, Ordering::Relaxed) {
                        *result.lock().unwrap() = Some((nonce, out));
                    }
                    n = n.wrapping_add(threads);
                }
                tried.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    let (nonce, out) = result.into_inner().unwrap().unwrap();
    (nonce, out, tried.into_inner())
}

fn coinbase(wallet: &mut Wallet, amount: u64) -> Transaction {
    let out = wallet.receive(amount);
    UnsignedTransaction::new(vec![], vec![out]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap()
}

/// Segments the greedy packing of [`SegmentWitness::collect_by_rows`]
/// needs for transactions of `rows` rows each.
fn segments_for(rows: &[usize], max_rows: usize) -> usize {
    let (mut segments, mut used) = (0, max_rows);
    for &r in rows {
        if used + r > max_rows && used > 0 {
            segments += 1;
            used = 0;
        }
        used += r;
    }
    segments
}

fn mine(args: &Args) -> AnyResult<()> {
    let params = ChainParams::MAINNET;
    let agg = params.aggregator;
    std::fs::create_dir_all(&args.data)?;

    let t = Instant::now();
    let seed = SeedText::new(params.pow);
    let path = args.data.join("dataset");
    if !path.exists() {
        println!(
            "generating the {} MB proof-of-work dataset (once per data directory)...",
            params.pow.dataset_bytes() >> 20
        );
    }
    let dataset = Dataset::load_or_generate(&seed, &path)?;
    println!("dataset: {} MB ready in {}", params.pow.dataset_bytes() >> 20, secs(t.elapsed()));
    let chain = open_chain(args, params, seed)?;
    let mut wallet = Wallet::open(&args.data.join("wallet"))?;

    if chain.tip()?.is_none() {
        let body = Body { inputs: vec![], outputs: vec![], proof: vec![] };
        let header = Header {
            prev_hash: EMPTY,
            height: 0,
            timestamp: now(),
            body_commitment: body.commitment(),
            state_root: chain.state_root()?,
            mix: EMPTY,
            nonce: [0u8; 32],
        };
        chain.init_genesis(&Block { header, body })?;
        println!("new chain in {}: genesis {}", args.data.display(), hex(&header.hash()));
    }
    let tip = chain.tip()?.unwrap();
    println!(
        "tip at height {} ({}); segments of 2^{} rows at rate 1/{}, up to {} per block; nodes at rate 1/{}",
        tip.height,
        short(&tip.hash()),
        agg.segment_log_n,
        1 << agg.segment.log_blowup,
        agg.max_segments,
        1 << agg.outer.log_blowup
    );

    let tx_rows = 2 + ROWS_PER_INPUT + 2 * ROWS_PER_OUTPUT;
    let coinbase_rows = 2 + ROWS_PER_OUTPUT;
    let mut mined = 0u64;
    while args.blocks == 0 || mined < args.blocks {
        let started = Instant::now();
        let tip = chain.tip()?.unwrap();
        let height = tip.height + 1;
        let subsidy = params.subsidy(height);

        // Transactions: the coinbase, then splits of the wallet's coins
        // while they fit the block's segments and size limits.
        let coins = {
            let rtxn = chain.env().read_txn()?;
            wallet.spendable(chain.utxo(), &rtxn)?
        };
        let balance = wallet.balance();
        let mut txs = vec![coinbase(&mut wallet, subsidy)];
        let mut rows = vec![coinbase_rows];
        let (mut n_in, mut n_out) = (0, 1);
        let mut spend = 0;
        for _ in coins.iter().take(args.txs) {
            rows.push(tx_rows);
            if segments_for(&rows, agg.segment_rows()) > agg.max_segments
                || n_in + 1 > params.max_inputs
                || n_out + 2 > params.max_outputs
            {
                break;
            }
            spend += 1;
            n_in += 1;
            n_out += 2;
        }
        txs.extend(wallet.split_all(&coins[..spend], 2));
        let build_time = started.elapsed();

        // Witnesses: apply the transactions in a transaction that is thrown
        // away, recording the tree paths.
        let (segments, statement, inputs, outputs) = {
            let mut wtxn = chain.env().write_txn()?;
            let utxo = chain.utxo();
            let prev_state_root = utxo.root(&wtxn)?;
            let first_output_position = utxo.next_position(&wtxn)?;
            let segments = SegmentWitness::collect_by_rows(utxo, &mut wtxn, &txs, agg.segment_rows())?;
            let new_state_root = utxo.root(&wtxn)?;
            wtxn.abort();
            let inputs: Vec<u64> = segments.iter().flat_map(|s| s.positions()).collect();
            let outputs: Vec<_> = segments.iter().flat_map(|s| s.outputs()).collect();
            let body = Body { inputs: inputs.clone(), outputs: outputs.clone(), proof: vec![] };
            let statement = Statement::from_block(&BlockStatement {
                height,
                prev_state_root,
                new_state_root,
                first_output_position,
                subsidy,
                body: &body,
            });
            (segments, statement, inputs, outputs)
        };
        // Record the new outputs before the block can be applied.
        wallet.save()?;

        println!(
            "block {height}: {} txs ({} in, {} out) in {} segment{}, wallet {} in {} coins",
            txs.len(),
            inputs.len(),
            outputs.len(),
            segments.len(),
            if segments.len() == 1 { "" } else { "s" },
            fmt_coins(balance),
            coins.len()
        );
        let t = Instant::now();
        let shape = chain.verifier().shape(segments.len());
        let plan_time = t.elapsed();
        let t = Instant::now();
        let report = |p: Progress| match p {
            Progress::Segment { index, count, elapsed } => {
                println!("  segment {}/{count} proven in {}", index + 1, secs(elapsed))
            }
            Progress::Node { segments, log_n, hash_log_n, root, elapsed } => println!(
                "  {} over {segments} segment{} (2^{log_n} + 2^{hash_log_n} rows) proven in {}",
                if root { "root node" } else { "node" },
                if segments == 1 { "" } else { "s" },
                secs(elapsed)
            ),
        };
        let proof = prove_block_with(&agg, &shape, &statement, &segments, args.jobs, &report);
        let prove_time = t.elapsed();

        let body = Body { inputs, outputs, proof };
        let timestamp = now().max(tip.timestamp + 1);
        let mut header = chain.template(&body, timestamp)?;
        let target = chain.expected_target(&tip)?;
        let t = Instant::now();
        let (nonce, out, hashes) = solve(&dataset, &header.pow_hash(), &target);
        let mine_time = t.elapsed();
        header.nonce = nonce;
        header.mix = out.mix;
        let block = Block { header, body };

        let t = Instant::now();
        chain.apply_block(&block, now())?;
        let verify_time = t.elapsed();
        mined += 1;
        println!(
            "  mined {} after {} hashes in {} (work 2^{:.1}); accepted in {}; {} KB proof",
            short(&header.hash()),
            hashes,
            secs(mine_time),
            work_bits(&target),
            secs(verify_time),
            block.body.proof.len() / 1000,
        );
        println!(
            "  total {} (build {}, plan {}, prove {}, mine {}, verify {})",
            secs(started.elapsed()),
            secs(build_time),
            secs(plan_time),
            secs(prove_time),
            secs(mine_time),
            secs(verify_time)
        );
    }
    Ok(())
}
