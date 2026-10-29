//! `tabminer`: a tabernacle node that follows the network's heaviest chain
//! and, by default, mines and proves blocks on it.
//!
//! ```text
//! tabminer [mine] [--data DIR] [--blocks N] [--txs N] [--jobs N] [--no-mine] [net options]
//! tabminer node [--data DIR] [net options]
//! tabminer show [--data DIR]
//!
//! net options: [--listen ADDR] [--peer ADDR]... [--seed HOST:PORT]... [--verbose]
//! ```
//!
//! With no command, `tabminer` mines. The data directory defaults to
//! `~/.tabernacle/tabminer` (`./tabminer-data` when `HOME` is unset).
//!
//! Every command starts from the fixed mainnet genesis. `mine` and `node`
//! listen for peers on UDP (port 7417 by default), contact the seeds and any
//! `--peer`, sync to the chain with the most work, relay new blocks, and
//! save the peers they found for next time.
//!
//! `mine` additionally builds blocks on the tip (unless `--no-mine` is
//! given, which makes it the same as `node`): a coinbase paying the
//! subsidy to the node's wallet (created on first use), plus up to `--txs`
//! transfers (368 by default, sixteen segments), each splitting one of the
//! wallet's outputs in two, within the block size limit. Each block is
//! proven (segments, then the aggregation tree), mined, applied through
//! full validation, and announced. If the network delivers a better tip
//! while a block is being proven or mined, the miner drops it and starts
//! over on the new tip. `--blocks 0` (the default) runs until interrupted.
//! `--jobs` bounds how many segments are proven at once.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tabminer::aggregate::{AggregateVerifier, Progress, Statement, prove_block_cancellable};
use tabminer::block::{Block, Body};
use tabminer::block_air::{SegmentWitness, pack};
use tabminer::chain::{BlockStatement, Chain, ChainParams};
use tabminer::node::{Config, DEFAULT_PORT, Event, Node};
use tabminer::poseidon2::digest_to_bytes;
use tabminer::pow::{Dataset, Digest, Nonce, PowOutput, SeedText, Target, hashimoto, nonce_from_u64};
use tabminer::transaction::{Sig, Transaction, UnsignedTransaction};
use tabminer::wallet::Wallet;

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage:
  tabminer [mine] [--data DIR] [--blocks N] [--txs N] [--jobs N] [--no-mine] [net options]
  tabminer node [--data DIR] [net options]
  tabminer show [--data DIR]

  --data DIR        chain and wallet directory (default ~/.tabernacle/tabminer)
  --blocks N        blocks to mine, 0 for no limit (default 0)
  --txs N           most transfers per block (default 368: sixteen segments)
  --jobs N          segments proven at once (default 2)
  --no-mine         follow the chain without mining (same as the node command)

net options:
  --listen ADDR     UDP address to listen on (default 0.0.0.0:7417)
  --peer ADDR       a peer to contact, host:port; may repeat
  --seed HOST:PORT  an extra seed node to resolve; may repeat
  --verbose         log every network message handled";

/// LMDB map size: an upper bound on the database, reserved as address space.
const MAP_SIZE: usize = 4 << 30;

/// How long the miner waits for the node to accept its block before moving
/// on.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);

struct Args {
    command: String,
    data: PathBuf,
    blocks: u64,
    txs: usize,
    jobs: usize,
    no_mine: bool,
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    seeds: Vec<String>,
    verbose: bool,
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
    let mut a = Args {
        command,
        data,
        blocks: 0,
        txs: 368,
        jobs: 2,
        no_mine: false,
        listen: SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
        peers: Vec::new(),
        seeds: Vec::new(),
        verbose: false,
    };
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        let number = |v: String| v.parse::<u64>().map_err(|_| format!("{flag}: not a number: {v}"));
        match flag.as_str() {
            "--data" => a.data = PathBuf::from(value()?),
            "--blocks" => a.blocks = number(value()?)?,
            "--txs" => a.txs = number(value()?)? as usize,
            "--jobs" => a.jobs = number(value()?)?.max(1) as usize,
            "--no-mine" => a.no_mine = true,
            "--listen" => {
                let v = value()?;
                a.listen = v.parse().map_err(|_| format!("--listen: not an address: {v}"))?;
            }
            "--peer" => {
                let v = value()?;
                let mut addrs = v.to_socket_addrs().map_err(|e| format!("--peer {v}: {e}"))?;
                a.peers.push(addrs.next().ok_or(format!("--peer {v}: no address"))?);
            }
            "--seed" => a.seeds.push(value()?),
            "--verbose" => a.verbose = true,
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
        "mine" if args.no_mine => node(&args),
        "mine" => mine(&args),
        "node" => node(&args),
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

fn open_chain(args: &Args, params: ChainParams, seed: SeedText) -> AnyResult<Arc<Chain<AggregateVerifier>>> {
    std::fs::create_dir_all(args.data.join("chain"))?;
    let chain =
        Chain::open(&args.data.join("chain"), MAP_SIZE, params, seed, AggregateVerifier::new(params.aggregator))?;
    chain.init_or_check_genesis()?;
    Ok(Arc::new(chain))
}

fn net_config(args: &Args) -> Config {
    Config {
        listen: args.listen,
        peers: args.peers.clone(),
        seeds: args.seeds.clone(),
        peers_file: Some(args.data.join("peers")),
        verbose: args.verbose,
    }
}

/// Starts the network node on its own thread; returns its event sender and
/// tip-change counter.
fn start_node(args: &Args, chain: &Arc<Chain<AggregateVerifier>>) -> AnyResult<(Sender<Event>, Arc<AtomicU64>)> {
    let (node, tx) = Node::bind(Arc::clone(chain), net_config(args))?;
    let tip_changes = node.tip_changes();
    println!("listening on {}", node.local_addr()?);
    std::thread::Builder::new().name("node".into()).spawn(move || node.run())?;
    Ok((tx, tip_changes))
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
    println!(
        "tip {} at height {}, state root {}, work 2^{:.1}",
        hex(&tip.hash()),
        tip.height,
        short(&tip.state_root),
        chain.tip_work()?.0.iter().rev().fold(0f64, |acc, l| acc * 2f64.powi(64) + *l as f64).log2()
    );
    Ok(())
}

fn node(args: &Args) -> AnyResult<()> {
    let params = ChainParams::MAINNET;
    let chain = open_chain(args, params, SeedText::new(params.pow))?;
    let tip = chain.tip()?.ok_or("no genesis")?;
    println!("tip at height {} ({})", tip.height, short(&tip.hash()));
    let (node, _tx) = Node::bind(chain, net_config(args))?;
    println!("listening on {}", node.local_addr()?);
    node.run();
    Ok(())
}

/// Searches nonces on every thread from a time-based start until one meets
/// `target` or `cancel` says to stop. Returns the nonce, its output and the
/// hashes tried.
fn solve(
    dataset: &Dataset,
    header_hash: &Digest,
    target: &Target,
    cancel: &(dyn Fn() -> bool + Sync),
) -> Option<(Nonce, PowOutput, u64)> {
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
                    if local % 64 == 0 && t == 0 && cancel() {
                        found.store(true, Ordering::Relaxed);
                    }
                    n = n.wrapping_add(threads);
                }
                tried.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    let (nonce, out) = result.into_inner().unwrap()?;
    Some((nonce, out, tried.into_inner()))
}

fn coinbase(wallet: &mut Wallet, amount: u64) -> Transaction {
    let out = wallet.receive(amount);
    UnsignedTransaction::new(vec![], vec![out]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap()
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
    let (events, tip_changes) = start_node(args, &chain)?;

    let tip = chain.tip()?.unwrap();
    println!(
        "tip at height {} ({}); segments of 2^{} rows at rate 1/{}, up to {} per block; nodes at rate 1/{}, wrap at 1/{}",
        tip.height,
        short(&tip.hash()),
        agg.segment_log_n,
        1 << agg.segment.log_blowup,
        agg.max_segments,
        1 << agg.outer.log_blowup,
        1 << agg.wrap.log_blowup
    );

    let mut mined = 0u64;
    while args.blocks == 0 || mined < args.blocks {
        let started = Instant::now();
        let generation = tip_changes.load(Ordering::Acquire);
        let tip_changed = || tip_changes.load(Ordering::Acquire) != generation;
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
        // Item counts: the coinbase, then one-input, two-output splits.
        let items = |t: usize| if t == 0 { (0, 1) } else { (1, 2) };
        // Size: header, body counts and outputs, input positions, and a
        // margin for the proof.
        let size = |spend: usize| 172 + 12 + spend * 5 + (1 + 2 * spend) * 40 + (256 << 10);
        let mut spend = 0;
        for _ in coins.iter().take(args.txs) {
            if pack(spend + 2, items, agg.segment_rows()).len() > agg.max_segments
                || size(spend + 1) > params.max_block_size
            {
                break;
            }
            spend += 1;
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
            let outputs: Vec<_> = segments.iter().flat_map(|s| s.commitments()).collect();
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
        // Record the new outputs before the block can be applied. Outputs
        // of a block that never lands are simply never spendable.
        wallet.save()?;

        println!(
            "proving block {height} on {}: {} txs ({} in, {} out) in {} segment{}, wallet {} in {} coins",
            short(&tip.hash()),
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
            Progress::Wrap { log_n, hash_log_n, elapsed } => {
                println!("  wrap (2^{log_n} + 2^{hash_log_n} rows) proven in {}", secs(elapsed))
            }
        };
        let Some(proof) =
            prove_block_cancellable(&agg, &shape, &statement, &segments, args.jobs, &report, &tip_changed)
        else {
            println!("  tip changed while proving block {height}; starting over");
            continue;
        };
        let prove_time = t.elapsed();

        let body = Body { inputs, outputs, proof };
        let timestamp = now().max(tip.timestamp + 1);
        let mut header = chain.template(&body, timestamp)?;
        let target = chain.expected_target(&tip)?;
        let t = Instant::now();
        let Some((nonce, out, hashes)) = solve(&dataset, &header.pow_hash(), &target, &tip_changed) else {
            println!("  tip changed while mining block {height}; starting over");
            continue;
        };
        let mine_time = t.elapsed();
        header.nonce = nonce;
        header.mix = out.mix;
        let block = Block { header, body };
        println!(
            "  mined {} after {} hashes in {} (work 2^{:.1}); {} KB proof",
            short(&header.hash()),
            hashes,
            secs(mine_time),
            work_bits(&target),
            block.body.proof.len() / 1000,
        );

        // The node applies and announces it; wait for the tip to move.
        let t = Instant::now();
        events.send(Event::Mined(block))?;
        while !tip_changed() && t.elapsed() < ACCEPT_TIMEOUT {
            std::thread::sleep(Duration::from_millis(10));
        }
        let accepted = chain.tip()?.unwrap().hash() == header.hash();
        if !accepted {
            println!("  lost block {height}: {} is not the tip", short(&header.hash()));
        }
        mined += u64::from(accepted);
        println!(
            "  total {} (build {}, plan {}, prove {}, mine {}, accept {})",
            secs(started.elapsed()),
            secs(build_time),
            secs(plan_time),
            secs(prove_time),
            secs(mine_time),
            secs(t.elapsed())
        );
    }
    if mined > 0 {
        // Let peers fetch the last block before the node goes away.
        println!("done; serving peers for a few seconds");
        std::thread::sleep(Duration::from_secs(5));
    }
    Ok(())
}
