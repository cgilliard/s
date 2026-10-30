//! `tabminer`: a tabernacle node with a wallet prompt. It follows the
//! network's heaviest chain, relays blocks and transactions, and by default
//! mines and proves blocks on it.
//!
//! ```text
//! tabminer [mine] [--data DIR] [--blocks N] [--jobs N] [--no-mine] [options]
//! tabminer node [--data DIR] [options]
//! tabminer show [--data DIR]
//! tabminer restore [--data DIR]
//!
//! options: [--listen ADDR] [--peer ADDR]... [--seed HOST:PORT]... [--verbose] [--no-prompt]
//! ```
//!
//! With no command, `tabminer` mines. The data directory defaults to
//! `~/.tabernacle/tabminer` (`./tabminer-data` when `HOME` is unset) and
//! holds the chain, the wallet, the peer list and `tabminer.log`.
//!
//! Every command starts from the fixed mainnet genesis. `mine` and `node`
//! listen for peers on UDP (port 3737 by default), contact the seeds and
//! any `--peer`, sync to the chain with the most work, relay new blocks and
//! transactions, and save the peers they found for next time. Logs go to
//! the log file; the terminal shows a prompt for wallet and status commands
//! (type `help`), unless `--no-prompt` sends the log to the terminal
//! instead.
//!
//! `mine` additionally builds blocks on the tip (unless `--no-mine` is
//! given, which makes it the same as `node`): the pooled transactions by
//! fee rate, within the block limits, and a reward paying the subsidy plus
//! their fees to the node's wallet. Each block is proven (segments, then
//! the aggregation tree), mined, applied through full validation, and
//! announced. If the network delivers a better tip while a block is being
//! proven or mined, the miner drops it and starts over on the new tip.
//! `--blocks 0` (the default) runs until `quit`. `--jobs` bounds how many
//! segments are proven at once.
//!
//! The wallet is created on first run with a 12-word BIP39 phrase, shown
//! once (and by `phrase`). `restore` rebuilds a wallet from a phrase in an
//! empty data directory; once the node has synced, `scan` finds its
//! outputs on chain from their memos.
//!
//! Payments use slate files: `send` writes one for the recipient, who
//! answers it with `receive`; `finalize` on the sender's side signs it and
//! pools the transaction. `cancel` replaces an unconfirmed payment with
//! one paying the inputs back, at a higher fee.

use std::io::{BufRead, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tabminer::aggregate::{AggregateVerifier, Progress, Statement};
use tabminer::block::{Block, Body};
use tabminer::block_air::{SegmentWitness, pack};
use tabminer::chain::{BlockStatement, Chain, ChainParams, DEFAULT_MAX_UNDO};
use tabminer::log;
use tabminer::mempool::{DEFAULT_CAPACITY, Mempool};
use tabminer::node::{Config, DEFAULT_PORT, DEFAULT_SYNC_POINT, Event, Mode, Node, SEEDS, Stats};
use tabminer::poseidon2::digest_to_bytes;
use tabminer::pow::{Dataset, Digest, Nonce, PowOutput, SeedText, Target, hashimoto, nonce_from_u64};
use tabminer::transaction::{Output, Sig, Transaction, UnsignedTransaction};
use tabminer::wallet::{Signed, Slate, State, Wallet};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage:
  tabminer [mine] [--data DIR] [--blocks N] [--jobs N] [--no-mine] [options]
  tabminer node [--data DIR] [options]
  tabminer show [--data DIR]
  tabminer restore [--data DIR]     rebuild a wallet from its 12-word phrase

  --data DIR        chain, wallet and log directory (default ~/.tabernacle/tabminer)
  --blocks N        blocks to mine, 0 for no limit (default 0)
  --jobs N          segments proven at once (default 2)
  --no-mine         follow the chain without mining (same as the node command)

options:
  --listen ADDR     UDP address to listen on (default 0.0.0.0:3737)
  --peer ADDR       a peer to contact, host:port; may repeat
  --seed HOST:PORT  an extra seed node to resolve; may repeat
  --no-seeds        do not contact the built-in seed nodes (for a local network)
  --sync-point N    when starting from genesis, fast-sync from the state N blocks
                    below the best header, checked by that block's chain proof
                    (default 144); 0 replays every block instead
  --max-undo-blocks N  keep undo records and bodies for the last N blocks
                    (default 1008, a week); older blocks keep only their
                    headers. Deeper reorganizations are refused, and snapshots
                    are served only within them; 0 keeps everything (archive)
  --verbose         log every network message handled
  --no-prompt       no wallet prompt; log to the terminal instead of the file";

const HELP: &str = "commands:
  status                    chain tip, peers, mempool, wallet totals
  peers                     known peers
  mempool                   pooled transactions
  balance                   confirmed, pending, reserved and locked funds
  outputs                   the wallet's outputs
  send AMOUNT FEE FILE      start a payment: write a slate for the recipient
  receive FILE [OUT]        answer a slate: add your output (writes OUT, default FILE.received)
  finalize FILE             sign an answered slate and pool the transaction
  cancel ID [FEE]           abandon a pending slate (freeing its inputs), or replace
                            an unconfirmed payment with one paying its inputs back
                            (FEE defaults to the smallest the network accepts)
  slates                    pending slates
  sent                      unconfirmed payments that can be cancelled
  scan                      find this wallet's outputs on chain (after a restore)
  prune                     forget unspent outputs the chain does not hold
  phrase                    show the wallet's 12-word recovery phrase
  quit                      stop the node
amounts are coins with up to eight decimals, e.g. 1.5";

/// LMDB map size: 1 TiB. It is only an upper bound, reserved as address
/// space: the file grows as data is written (a Bitcoin-sized output set
/// takes under 30 GB) and is never allocated ahead.
const MAP_SIZE: usize = 1 << 40;

/// How long the miner waits for the node to accept its block before moving
/// on.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);

struct Args {
    command: String,
    data: PathBuf,
    blocks: u64,
    jobs: usize,
    no_mine: bool,
    no_prompt: bool,
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    seeds: Vec<String>,
    verbose: bool,
    sync_point: u32,
    max_undo: u32,
    no_seeds: bool,
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
        jobs: 2,
        no_mine: false,
        no_prompt: false,
        listen: SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
        peers: Vec::new(),
        seeds: Vec::new(),
        verbose: false,
        sync_point: DEFAULT_SYNC_POINT,
        max_undo: DEFAULT_MAX_UNDO,
        no_seeds: false,
    };
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        let number = |v: String| v.parse::<u64>().map_err(|_| format!("{flag}: not a number: {v}"));
        match flag.as_str() {
            "--data" => a.data = PathBuf::from(value()?),
            "--blocks" => a.blocks = number(value()?)?,
            "--jobs" => a.jobs = number(value()?)?.max(1) as usize,
            "--no-mine" => a.no_mine = true,
            "--no-prompt" => a.no_prompt = true,
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
            "--no-seeds" => a.no_seeds = true,
            "--verbose" => a.verbose = true,
            "--sync-point" => a.sync_point = number(value()?)? as u32,
            "--max-undo-blocks" => a.max_undo = number(value()?)? as u32,
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
        "mine" => run(&args, !args.no_mine),
        "node" => run(&args, false),
        "show" => show(&args),
        "restore" => restore(&args),
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

/// Parses coins with up to eight decimals into base units.
fn parse_coins(s: &str) -> Option<u64> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > 8 {
        return None;
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let frac: u64 = if frac.is_empty() { 0 } else { format!("{frac:0<8}").parse().ok()? };
    whole.checked_mul(100_000_000)?.checked_add(frac)
}

/// Expected hashes to meet `target`: `2^248 / (target + 1)`, as log2.
fn work_bits(target: &Target) -> f64 {
    let t = target.0.iter().rev().fold(0f64, |acc, b| acc * 256.0 + *b as f64);
    248.0 - (t + 1.0).log2()
}

fn open_chain(args: &Args, params: ChainParams, seed: SeedText) -> AnyResult<Arc<Chain<AggregateVerifier>>> {
    std::fs::create_dir_all(args.data.join("chain"))?;
    let verifier = AggregateVerifier::new(params.aggregator, params.emission);
    let chain = Chain::open(&args.data.join("chain"), MAP_SIZE, params, seed, verifier)?
        .with_max_undo((args.max_undo > 0).then_some(args.max_undo));
    chain.init_or_check_genesis()?;
    Ok(Arc::new(chain))
}

fn net_config(args: &Args) -> Config {
    Config {
        listen: args.listen,
        peers: args.peers.clone(),
        seeds: if args.no_seeds { Vec::new() } else { SEEDS.iter().map(|s| s.to_string()).collect() }
            .into_iter()
            .chain(args.seeds.iter().cloned())
            .collect(),
        peers_file: Some(args.data.join("peers")),
        verbose: args.verbose,
        sync_point: (args.sync_point > 0).then_some(args.sync_point),
    }
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
        match chain.body_by_hash(&header.hash())? {
            Some(body) => println!(
                "{:>6}  {}  {:>19}  {:>6} {:>7}  {:>6} KB",
                h,
                short(&header.hash()),
                header.timestamp,
                body.inputs.len(),
                body.outputs.len(),
                body.proof.len() / 1000
            ),
            // Below a fast-sync snapshot or the undo window only headers
            // are kept.
            None => println!("{:>6}  {}  {:>19}  (header only)", h, short(&header.hash()), header.timestamp),
        }
    }
    if let Some(floor) = chain.floor()? {
        println!("fast-synced from the state after block {floor}, verified by its chain proof");
    }
    println!(
        "tip {} at height {}, state root {}, work 2^{:.1}",
        hex(&tip.hash()),
        tip.height,
        short(&tip.state_root),
        log2_u256(chain.tip_work()?)
    );
    Ok(())
}

fn log2_u256(w: tabminer::difficulty::U256) -> f64 {
    // Genesis alone has no work; show 2^0 rather than 2^-inf.
    w.0.iter().rev().fold(0f64, |acc, l| acc * 2f64.powi(64) + *l as f64).max(1.0).log2()
}

/// Everything the prompt and the miner share.
struct Ctx {
    params: ChainParams,
    chain: Arc<Chain<AggregateVerifier>>,
    mempool: Arc<Mutex<Mempool>>,
    wallet: Arc<Wallet>,
    events: Sender<Event>,
    stats: Arc<Mutex<Stats>>,
    tip_changes: Arc<AtomicU64>,
    syncing: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    mining: bool,
    /// The reward output of the block being mined, forgotten on quit.
    in_flight: Mutex<Option<tabminer::transaction::Commitment>>,
}

/// Runs the node, the miner if `mining`, and the prompt (or waits) until
/// `quit`.
fn run(args: &Args, mining: bool) -> AnyResult<()> {
    let params = ChainParams::MAINNET;
    std::fs::create_dir_all(&args.data)?;
    let log_path = args.data.join("tabminer.log");
    log::init(Some(&log_path), args.no_prompt)?;
    if !args.no_prompt {
        println!("logging to {}", log_path.display());
    }
    log::line(&format!("tabminer starting in {}", args.data.display()));

    let seed = SeedText::new(params.pow);
    let dataset = if mining {
        let t = Instant::now();
        let path = args.data.join("dataset");
        if !path.exists() {
            let msg = format!(
                "generating the {} MB proof-of-work dataset (once per data directory)...",
                params.pow.dataset_bytes() >> 20
            );
            if !args.no_prompt {
                println!("{msg}");
            }
            log::line(&msg);
        }
        let dataset = Dataset::load_or_generate(&seed, &path)?;
        log::line(&format!("dataset: {} MB ready in {}", params.pow.dataset_bytes() >> 20, secs(t.elapsed())));
        Some(Arc::new(dataset))
    } else {
        None
    };
    let chain = open_chain(args, params, seed)?;
    let pruned = chain.prune_undo()?;
    if pruned > 0 {
        log::line(&format!("pruned {pruned} undo records beyond the last {} blocks", args.max_undo));
    }
    if args.max_undo > 0 && args.sync_point > args.max_undo {
        log::line(&format!(
            "warning: --sync-point {} is deeper than --max-undo-blocks {}: this node cannot serve such snapshots",
            args.sync_point, args.max_undo
        ));
    }
    if mining {
        // The miner proves membership of its wrap in the plan of every
        // segment count: computed once (about a minute), then kept.
        let t = Instant::now();
        let path = args.data.join("plan");
        let saved = std::fs::read(&path).ok();
        let leaves = saved
            .as_ref()
            .and_then(|b| b.chunks_exact(32).map(tabminer::poseidon2::digest_from_bytes).collect::<Option<Vec<_>>>());
        if leaves.is_none() {
            let msg = "planning every segment count for the chain proofs (once per data directory)...";
            if !args.no_prompt {
                println!("{msg}");
            }
            log::line(msg);
        }
        chain.verifier().plan_tree(leaves);
        let bytes = chain.verifier().plan_leaves_bytes();
        if saved.as_deref() != Some(&bytes[..]) {
            std::fs::write(&path, &bytes)?;
        }
        log::line(&format!("plan ready in {}", secs(t.elapsed())));
    }
    let (wallet, created) = Wallet::open(&args.data.join("wallet"))?;
    if let Some(phrase) = created {
        log::line("created a new wallet");
        println!("\nnew wallet; its recovery phrase is:\n\n    {phrase}\n");
        println!("write it down and keep it safe: it is the only way to restore the wallet's funds\n");
    }
    let wallet = Arc::new(wallet);
    let mempool = Arc::new(Mutex::new(Mempool::new(DEFAULT_CAPACITY)));
    let (node, events) = Node::bind(Arc::clone(&chain), Arc::clone(&mempool), net_config(args))?;
    let stats = node.stats();
    let syncing = node.syncing();
    let tip_changes = node.tip_changes();
    let listening = format!("listening on {}", node.local_addr()?);
    log::line(&listening);
    let node_thread = std::thread::Builder::new().name("node".into()).spawn(move || node.run())?;
    let tip = chain.tip()?.ok_or("no genesis")?;
    let tip_line = format!("tip at height {} ({})", tip.height, short(&tip.hash()));
    log::line(&tip_line);
    if !args.no_prompt {
        println!("{listening}; {tip_line}; type help for commands");
    }

    let ctx = Arc::new(Ctx {
        params,
        chain,
        mempool,
        wallet,
        events: events.clone(),
        stats,
        tip_changes,
        syncing,
        stop: Arc::new(AtomicBool::new(false)),
        mining,
        in_flight: Mutex::new(None),
    });
    // The chain ends at the schedule's final block: once the tip reaches
    // it, the node has nothing left to do.
    {
        let ctx = Arc::clone(&ctx);
        std::thread::Builder::new().name("final-block".into()).spawn(move || {
            let last = ctx.params.final_height();
            loop {
                if ctx.chain.tip().ok().flatten().is_some_and(|t| t.height >= last) {
                    let msg = format!("the chain has reached its final block, height {last}; exiting");
                    log::line(&msg);
                    println!("\n{msg}");
                    // Let the node announce the block before going.
                    std::thread::sleep(Duration::from_secs(5));
                    std::process::exit(0);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        })?;
    }
    // A restored wallet finds its outputs once the node has caught up.
    if ctx.wallet.scan_pending()? {
        let ctx = Arc::clone(&ctx);
        std::thread::Builder::new().name("restore-scan".into()).spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let peers = ctx.stats.lock().unwrap().peers.iter().any(|p| p.live);
                if !peers || ctx.syncing.load(Ordering::Acquire) {
                    continue;
                }
                let found = ctx
                    .chain
                    .env()
                    .read_txn()
                    .map_err(|e| e.to_string())
                    .and_then(|rtxn| ctx.wallet.scan(ctx.chain.utxo(), &rtxn).map_err(|e| e.to_string()));
                match found {
                    Ok((n, total)) => {
                        log::line(&format!("restored wallet: found {n} outputs worth {}", fmt_coins(total)));
                        ctx.wallet.clear_scan_pending().ok();
                    }
                    Err(e) => log::line(&format!("restored wallet: scan failed: {e}")),
                }
                return;
            }
        })?;
    }
    let miner = match dataset {
        Some(dataset) => {
            let ctx = Arc::clone(&ctx);
            let (blocks, jobs) = (args.blocks, args.jobs);
            Some(std::thread::Builder::new().name("miner".into()).spawn(move || {
                if let Err(e) = mine(&ctx, &dataset, blocks, jobs) {
                    log::line(&format!("miner stopped: {e}"));
                }
            })?)
        }
        None => None,
    };

    if args.no_prompt {
        match miner {
            // A bounded mining run ends the process, after letting peers
            // fetch the last block.
            Some(m) if args.blocks > 0 => {
                m.join().ok();
                log::line("done; serving peers for a few seconds");
                std::thread::sleep(Duration::from_secs(5));
            }
            Some(m) => {
                m.join().ok();
            }
            None => loop {
                std::thread::sleep(Duration::from_secs(3600));
            },
        }
    } else {
        prompt(&ctx);
        // Exit without waiting for the miner: an unfinished proof is simply
        // dropped, and every database write is an LMDB transaction, so
        // nothing is left half done. The node gets a moment to save its
        // peer list.
        ctx.stop.store(true, Ordering::Release);
        drop(miner);
        // The block being mined will never land: drop its reward record,
        // unless its block already did.
        if let Some(c) = ctx.in_flight.lock().unwrap().take() {
            let held =
                ctx.chain.env().read_txn().ok().is_some_and(|r| ctx.chain.utxo().contains(&r, &c).unwrap_or(false));
            if !held {
                ctx.wallet.forget(&c).ok();
            }
        }
        events.send(Event::Stop).ok();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !node_thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        log::line("tabminer stopped");
        std::process::exit(0);
    }
    events.send(Event::Stop).ok();
    node_thread.join().ok();
    log::line("tabminer stopped");
    Ok(())
}

/// Reads commands from standard input until `quit` or end of input.
fn prompt(ctx: &Ctx) {
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        print!("> ");
        std::io::stdout().flush().ok();
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(&cmd) = words.first() else {
            continue;
        };
        if matches!(cmd, "quit" | "exit") {
            break;
        }
        if let Err(e) = command(ctx, cmd, &words[1..]) {
            println!("error: {e}");
        }
    }
}

fn command(ctx: &Ctx, cmd: &str, args: &[&str]) -> AnyResult<()> {
    match cmd {
        "help" => println!("{HELP}"),
        "status" => {
            let tip = ctx.chain.tip()?.ok_or("no genesis")?;
            // One LMDB read transaction per thread at a time: the work is
            // read before the one the balance needs.
            let work = log2_u256(ctx.chain.tip_work()?);
            let stats = ctx.stats.lock().unwrap().clone();
            let pool = ctx.mempool.lock().unwrap();
            let rtxn = ctx.chain.env().read_txn()?;
            let b = ctx.wallet.balance(ctx.chain.utxo(), &rtxn)?;
            println!(
                "tip      height {} {} at {}, work 2^{work:.1}",
                tip.height,
                short(&tip.hash()),
                log::timestamp_of(tip.timestamp)
            );
            println!(
                "peers    {} live of {} known; {} downloads, {} queued, {} orphans",
                stats.peers.iter().filter(|p| p.live).count(),
                stats.peers.len(),
                stats.downloads,
                stats.wanted,
                stats.orphans
            );
            match (stats.mode, stats.parts) {
                (Some(Mode::Headers), _) => println!("sync     fast sync: downloading headers"),
                (Some(Mode::Snapshot), Some((have, all))) => {
                    println!("sync     fast sync: {have} of {all} state parts")
                }
                (Some(Mode::Snapshot), None) => println!("sync     fast sync: fetching the snapshot block"),
                _ if ctx.syncing.load(Ordering::Acquire) => println!("sync     catching up"),
                _ => println!("sync     up to date"),
            }
            println!("mempool  {} transactions, {} KB", pool.len(), pool.bytes() / 1000);
            println!(
                "wallet   {} confirmed, {} pending, {} reserved, {} locked",
                fmt_coins(b.confirmed),
                fmt_coins(b.pending),
                fmt_coins(b.reserved),
                fmt_coins(b.locked)
            );
            println!("mining   {}", if ctx.mining { "on" } else { "off" });
        }
        "peers" => {
            let stats = ctx.stats.lock().unwrap().clone();
            if stats.peers.is_empty() {
                println!("no peers");
            }
            for p in &stats.peers {
                println!(
                    "{:<24} {:<8} {:<6} {}",
                    p.addr,
                    p.height.map_or("?".to_string(), |h| format!("h {h}")),
                    if p.live { "live" } else { "silent" },
                    if p.handshaken { "handshaken" } else { "" }
                );
            }
        }
        "mempool" => {
            let pool = ctx.mempool.lock().unwrap();
            println!("{} transactions, {} bytes", pool.len(), pool.bytes());
            for e in pool.entries() {
                println!("  {}  {} bytes  fee {}", short(&e.txid), e.size, fmt_coins(e.fee as u128));
            }
        }
        "balance" => {
            let rtxn = ctx.chain.env().read_txn()?;
            let b = ctx.wallet.balance(ctx.chain.utxo(), &rtxn)?;
            println!("confirmed {}  spendable", fmt_coins(b.confirmed));
            println!("pending   {}  incoming, not yet on chain", fmt_coins(b.pending));
            println!("reserved  {}  held for a slate not yet finalized", fmt_coins(b.reserved));
            println!("locked    {}  signed, being sent, not yet confirmed", fmt_coins(b.locked));
        }
        "outputs" => {
            let rtxn = ctx.chain.env().read_txn()?;
            let outputs = ctx.wallet.outputs()?;
            if outputs.is_empty() {
                println!("no outputs");
            }
            for o in outputs {
                let held = ctx.chain.utxo().contains(&rtxn, &o.commitment)?;
                let state = match (o.state, held) {
                    (State::Unspent, true) => "confirmed",
                    (State::Unspent, false) => "pending",
                    (State::Reserved, _) => "reserved",
                    (State::Spent, true) => "locked",
                    (State::Spent, false) => "spent",
                };
                println!(
                    "{}  {:>20}  {:<9}  {} signatures left{}  {}",
                    short(&o.commitment),
                    fmt_coins(o.amount as u128),
                    state,
                    o.signatures_left(),
                    if o.recovered { ", recovered" } else { "" },
                    log::timestamp_of(o.created)
                );
            }
        }
        "send" => {
            let [amount, fee, file] = args else {
                return Err("usage: send AMOUNT FEE FILE".into());
            };
            let amount = parse_coins(amount).ok_or("bad amount")?;
            let fee = parse_coins(fee).ok_or("bad fee")?;
            let rtxn = ctx.chain.env().read_txn()?;
            let slate = ctx.wallet.send(amount, fee, ctx.chain.utxo(), &rtxn)?;
            std::fs::write(file, slate.to_bytes())?;
            println!(
                "slate {} written to {}: {} coins plus {} fee from {} inputs; send it to the recipient",
                &slate.id_hex()[..16],
                file,
                fmt_coins(amount as u128),
                fmt_coins(fee as u128),
                slate.inputs.len()
            );
        }
        "receive" => {
            let (file, out) = match args {
                [file] => (file.to_string(), format!("{file}.received")),
                [file, out] => (file.to_string(), out.to_string()),
                _ => return Err("usage: receive FILE [OUT]".into()),
            };
            if out == file {
                return Err("the answered slate must not overwrite the one received".into());
            }
            let file = file.as_str();
            let out = out.as_str();
            let mut slate = read_slate(file)?;
            ctx.wallet.receive_slate(&mut slate)?;
            std::fs::write(out, slate.to_bytes())?;
            println!(
                "receiving {} coins (fee {}); answered slate written to {}; return it to the sender",
                fmt_coins(slate.amount as u128),
                fmt_coins(slate.fee as u128),
                out
            );
        }
        "finalize" => {
            let [file] = args else {
                return Err("usage: finalize FILE".into());
            };
            let slate = read_slate(file)?;
            let signed = ctx.wallet.finalize(&slate)?;
            submit(ctx, signed);
        }
        "cancel" => {
            let (id, fee) = match args {
                [id] => (*id, None),
                [id, fee] => (*id, Some(parse_coins(fee).ok_or("bad fee")?)),
                _ => return Err("usage: cancel ID [FEE]".into()),
            };
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            let slate = ctx.wallet.pending_slates()?.into_iter().map(|(s, _)| s).find(|s| hex(s).starts_with(id));
            if let Some(slate) = slate {
                ctx.wallet.cancel_slate(&slate)?;
                println!("slate cancelled; its inputs are spendable again");
                return Ok(());
            }
            let rtxn = ctx.chain.env().read_txn()?;
            let sent = ctx.wallet.sent(ctx.chain.utxo(), &rtxn)?;
            drop(rtxn);
            let s = sent
                .into_iter()
                .find(|s| hex(&digest_to_bytes(&s.txid)).starts_with(id))
                .ok_or("no pending slate or unconfirmed payment starts with that id")?;
            let signed = ctx.wallet.cancel_sent(&s.txid, fee)?;
            println!(
                "payment {} replaced; the inputs come back less a fee of {}",
                short(&s.txid),
                fmt_coins(signed.tx.balance() as u128)
            );
            submit(ctx, signed);
        }
        "sent" => {
            let rtxn = ctx.chain.env().read_txn()?;
            let sent = ctx.wallet.sent(ctx.chain.utxo(), &rtxn)?;
            if sent.is_empty() {
                println!("no unconfirmed payments");
            }
            for s in sent {
                println!(
                    "{}  fee {}  {} inputs  {}  (cancel from {})",
                    hex_digest(&s.txid),
                    fmt_coins(s.fee as u128),
                    s.inputs.len(),
                    log::timestamp_of(s.created),
                    fmt_coins(Wallet::min_replacement_fee(&s) as u128)
                );
            }
        }
        "scan" => {
            let rtxn = ctx.chain.env().read_txn()?;
            let (n, total) = ctx.wallet.scan(ctx.chain.utxo(), &rtxn)?;
            println!("found {n} outputs worth {}", fmt_coins(total));
        }
        "slates" => {
            let slates = ctx.wallet.pending_slates()?;
            if slates.is_empty() {
                println!("no pending slates");
            }
            for (id, reserved) in slates {
                println!(
                    "{}  {} reserved",
                    id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    fmt_coins(reserved)
                );
            }
        }
        "prune" => {
            let rtxn = ctx.chain.env().read_txn()?;
            let n = ctx.wallet.prune_pending(ctx.chain.utxo(), &rtxn)?;
            println!("{n} pending outputs forgotten");
        }
        "phrase" => {
            println!("{}", ctx.wallet.phrase()?);
            println!("anyone with these words (and the passphrase, if one was used) can take the funds");
        }
        _ => println!("unknown command {cmd}; type help"),
    }
    Ok(())
}

fn hex_digest(d: &Digest) -> String {
    hex(d)
}

/// Pools a signed transaction and reports it, with a warning for inputs
/// that made their last signature.
fn submit(ctx: &Ctx, signed: Signed) {
    let txid = signed.tx.txid();
    if !signed.last_signatures.is_empty() {
        println!(
            "warning: this was the last signature {} can make; it cannot be cancelled again",
            if signed.last_signatures.len() == 1 { "an input" } else { "some inputs" }
        );
    }
    match ctx.events.send(Event::Transaction(signed.tx)) {
        Ok(()) => println!("transaction {} signed and sent to the pool", short(&txid)),
        Err(_) => println!("transaction {} signed, but the node has stopped", short(&txid)),
    }
}

/// Rebuilds a wallet from its phrase in an empty data directory.
fn restore(args: &Args) -> AnyResult<()> {
    let dir = args.data.join("wallet");
    if dir.join("data.mdb").exists() {
        return Err(format!("{} already has a wallet; restore into another --data directory", dir.display()).into());
    }
    let stdin = std::io::stdin();
    let mut line = String::new();
    print!("recovery phrase (12 words): ");
    std::io::stdout().flush()?;
    stdin.lock().read_line(&mut line)?;
    let phrase = line.trim().to_string();
    tabminer::bip39::entropy(&phrase)?;
    let mut pass = String::new();
    print!("passphrase (empty if none): ");
    std::io::stdout().flush()?;
    stdin.lock().read_line(&mut pass)?;
    std::fs::create_dir_all(&args.data)?;
    Wallet::restore(&dir, &phrase, pass.trim_end_matches(['\r', '\n']))?;
    println!("wallet restored in {}", dir.display());
    println!("start tabminer with this --data directory: once it has synced, it finds the wallet's outputs");
    Ok(())
}

fn read_slate(file: &str) -> AnyResult<Slate> {
    let bytes = std::fs::read(Path::new(file))?;
    Slate::from_bytes(&bytes).ok_or_else(|| format!("{file} is not a slate").into())
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

/// The block reward transaction and the wallet's new output in it.
fn reward(wallet: &Wallet, amount: u64) -> AnyResult<(Transaction, Output)> {
    let out = wallet.receive(amount)?;
    Ok((UnsignedTransaction::new(vec![], vec![out]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap(), out))
}

/// The mining loop: builds, proves, mines and submits blocks on the tip
/// until `blocks` are accepted (0 for no limit) or the node stops.
fn mine(ctx: &Ctx, dataset: &Dataset, blocks: u64, jobs: usize) -> AnyResult<()> {
    let params = ctx.params;
    let agg = params.aggregator;
    let chain = &ctx.chain;
    let wallet = &ctx.wallet;
    let tip = chain.tip()?.unwrap();
    log::line(&format!(
        "mining from height {}; segments of 2^{} rows at rate 1/{}, up to {} per block; nodes at rate 1/{}, wrap at 1/{}",
        tip.height,
        agg.segment_log_n,
        1 << agg.segment.log_blowup,
        agg.max_segments,
        1 << agg.outer.log_blowup,
        1 << agg.wrap.log_blowup
    ));

    let mut mined = 0u64;
    let mut waited = false;
    while !ctx.stop.load(Ordering::Acquire) && (blocks == 0 || mined < blocks) {
        // Mining on a stale tip wastes the proof: wait until caught up.
        if ctx.syncing.load(Ordering::Acquire) {
            if !waited {
                log::line("waiting for the node to catch up before mining");
                waited = true;
            }
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }
        waited = false;
        let started = Instant::now();
        let generation = ctx.tip_changes.load(Ordering::Acquire);
        let cancel = || ctx.stop.load(Ordering::Acquire) || ctx.tip_changes.load(Ordering::Acquire) != generation;
        let tip = chain.tip()?.unwrap();
        let height = tip.height + 1;
        if height > params.final_height() {
            log::line("the chain has reached its final block; nothing left to mine");
            break;
        }
        let subsidy = params.subsidy(height);

        // Transactions: the reward, then the pooled ones by fee rate while
        // they fit the block's segment and size limits. Size: header, body
        // counts, outputs, input positions and a margin for the proof.
        let size = |ins: usize, outs: usize| 172 + 12 + ins * 5 + outs * 40 + (256 << 10);
        let fits = |ins: usize, outs: usize, items: &dyn Fn(usize) -> (usize, usize), n: usize| {
            pack(n, items, agg.segment_rows()).len() <= agg.max_segments && size(ins, outs) <= params.max_block_size
        };
        let pooled: Vec<Transaction> = ctx.mempool.lock().unwrap().select(|chosen| {
            let ins: usize = chosen.iter().map(|t| t.inputs.len()).sum();
            let outs: usize = 1 + chosen.iter().map(|t| t.outputs.len()).sum::<usize>();
            let items =
                |t: usize| if t == 0 { (0, 1) } else { (chosen[t - 1].inputs.len(), chosen[t - 1].outputs.len()) };
            fits(ins, outs, &items, chosen.len() + 1)
        });
        let fees = Mempool::fees(&pooled);
        let balance = {
            let rtxn = chain.env().read_txn()?;
            wallet.balance(chain.utxo(), &rtxn)?
        };
        let (reward_tx, reward_out) = reward(wallet, subsidy + fees)?;
        *ctx.in_flight.lock().unwrap() = Some(reward_out.commitment);
        // A block that never gets mined leaves no record behind.
        let abandon = || {
            if let Err(e) = wallet.forget(&reward_out.commitment) {
                log::line(&format!("  forgetting the reward of block {height}: {e}"));
            }
        };
        let mut txs = vec![reward_tx];
        txs.extend(pooled);
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
            let outputs: Vec<_> = segments.iter().flat_map(|s| s.block_outputs()).collect();
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

        log::line(&format!(
            "proving block {height} on {}: {} txs ({} in, {} out, {} in fees) in {} segment{}, wallet {} confirmed",
            short(&tip.hash()),
            txs.len(),
            inputs.len(),
            outputs.len(),
            fmt_coins(fees as u128),
            segments.len(),
            if segments.len() == 1 { "" } else { "s" },
            fmt_coins(balance.confirmed)
        ));
        // The chain proof builds on the previous block's.
        let prev = if height > 1 { chain.proof_statement(height - 1)? } else { None };
        let t = Instant::now();
        chain.verifier().shape(segments.len());
        let plan_time = t.elapsed();
        let t = Instant::now();
        let report = |p: Progress| match p {
            Progress::Segment { index, count, elapsed } => {
                log::line(&format!("  segment {}/{count} proven in {}", index + 1, secs(elapsed)))
            }
            Progress::Node { segments, log_n, hash_log_n, root, elapsed } => log::line(&format!(
                "  {} over {segments} segment{} (2^{log_n} + 2^{hash_log_n} rows) proven in {}",
                if root { "root node" } else { "node" },
                if segments == 1 { "" } else { "s" },
                secs(elapsed)
            )),
            Progress::Wrap { log_n, hash_log_n, elapsed } => {
                log::line(&format!("  wrap (2^{log_n} + 2^{hash_log_n} rows) proven in {}", secs(elapsed)))
            }
            Progress::Chain { elapsed } => log::line(&format!("  chain step proven in {}", secs(elapsed))),
        };
        let prev_ref = prev.as_ref().map(|(st, proof)| (height - 1, st, proof.as_slice()));
        let proof = chain.verifier().prove_block(height, &statement, &segments, prev_ref, jobs, &report, &cancel);
        let Some(proof) = proof else {
            abandon();
            if ctx.stop.load(Ordering::Acquire) {
                break;
            }
            log::line(&format!("  tip changed while proving block {height}; starting over"));
            continue;
        };
        let prove_time = t.elapsed();

        let body = Body { inputs, outputs, proof };
        let timestamp = now().max(tip.timestamp + 1);
        let mut header = chain.template(&body, timestamp)?;
        let target = chain.expected_target(&tip)?;
        let t = Instant::now();
        let Some((nonce, out, hashes)) = solve(dataset, &header.pow_hash(), &target, &cancel) else {
            abandon();
            if ctx.stop.load(Ordering::Acquire) {
                break;
            }
            log::line(&format!("  tip changed while mining block {height}; starting over"));
            continue;
        };
        let mine_time = t.elapsed();
        header.nonce = nonce;
        header.mix = out.mix;
        let block = Block { header, body };
        log::line(&format!(
            "  mined {} after {} hashes in {} (work 2^{:.1}); {} KB proof",
            short(&header.hash()),
            hashes,
            secs(mine_time),
            work_bits(&target),
            block.body.proof.len() / 1000,
        ));

        // The node applies and announces it; wait for the tip to move.
        let t = Instant::now();
        ctx.events.send(Event::Mined(block))?;
        while !cancel() && t.elapsed() < ACCEPT_TIMEOUT {
            std::thread::sleep(Duration::from_millis(10));
        }
        let accepted = chain.tip()?.unwrap().hash() == header.hash();
        if !accepted {
            // A side block may yet win a reorganization, so its reward stays
            // on record; a block the node did not keep at all is forgotten.
            if chain.entry(&header.hash())?.is_some_and(|e| !e.invalid) {
                log::line(&format!("  lost block {height}: {} is a side block, not the tip", short(&header.hash())));
            } else {
                abandon();
                log::line(&format!("  lost block {height}: {} was not accepted", short(&header.hash())));
            }
        }
        mined += u64::from(accepted);
        log::line(&format!(
            "  total {} (build {}, plan {}, prove {}, mine {}, accept {})",
            secs(started.elapsed()),
            secs(build_time),
            secs(plan_time),
            secs(prove_time),
            secs(mine_time),
            secs(t.elapsed())
        ));
    }
    Ok(())
}
