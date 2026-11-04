//! The binary at scale: a large unspent set, made at once behind genesis
//! (`--debug-fill-outputs`, proofs unchecked), then a full block applied
//! on it and a fresh node fast-syncing it. `TABMINER_SCALE_OUTPUTS` sets
//! the set's size: 2,000,000 by default, as every push runs it, and
//! 170,000,000 (a Bitcoin-sized set, about 12 GB) nightly
//! (`.github/workflows/scale.yml`). The data directories go under the
//! system's temporary directory (`TMPDIR`), which needs room for the set,
//! twice for the fast sync.
//!
//! Each test prints its timings as `SCALE` lines, one fact a line, for
//! comparing runs: `SCALE <test> <what> <value>`.

#![cfg(feature = "dev")]

mod common;

use common::{Proc, TempDir};
use std::time::{Duration, Instant};

/// The set's size: `TABMINER_SCALE_OUTPUTS`, or 2,000,000.
fn outputs() -> u64 {
    std::env::var("TABMINER_SCALE_OUTPUTS").ok().and_then(|v| v.parse().ok()).unwrap_or(2_000_000)
}

/// Generous bounds for steps that scale with the set: an hour, plus a
/// minute per million outputs.
fn scaled(n: u64) -> u64 {
    3600 + 60 * (n / 1_000_000)
}

fn report(test: &str, what: &str, value: impl std::fmt::Display) {
    println!("SCALE {test} {what} {value}");
}

/// The lines of a node's log containing `text`.
fn log_lines(p: &Proc, text: &str) -> Vec<String> {
    let log = std::fs::read_to_string(p.data.join("tabminer.log")).unwrap_or_default();
    log.lines().filter(|l| l.contains(text)).map(str::to_string).collect()
}

/// The number of seconds in `line` after `label`, as the log prints them
/// (`accept 1.06s`).
fn secs_after(line: &str, label: &str) -> Option<f64> {
    let rest = &line[line.find(label)? + label.len()..];
    rest.split(|c: char| !(c.is_ascii_digit() || c == '.')).find(|s| !s.is_empty())?.parse().ok()
}

/// Waits up to `secs` for a line of `p`'s log containing `text`; the time
/// it took.
fn wait_log(p: &mut Proc, text: &str, secs: u64) -> Duration {
    let start = Instant::now();
    p.expect_log(text, secs);
    start.elapsed()
}

/// The tip line of `status`: height and hash.
fn tip(p: &mut Proc) -> String {
    p.send("status");
    p.expect("the tip", 30, |l| l.starts_with("tip      height ")).trim().to_string()
}

/// A miner whose set holds `n` outputs, mining `blocks` full blocks of
/// random spends of them and random outputs.
fn filled_miner(name: &'static str, dir: &TempDir, n: u64, blocks: u64) -> (Proc, Duration) {
    let start = Instant::now();
    let (n_arg, blocks_arg) = (n.to_string(), blocks.to_string());
    let args = [
        "mine",
        "--debug-no-validate-proofs",
        "--debug-fill-outputs",
        &n_arg,
        "--debug-fill",
        "100000,100000",
        "--blocks",
        &blocks_arg,
    ];
    let p = Proc::start_waiting(name, &dir.0, &args, &[], scaled(n));
    (p, start.elapsed())
}

/// A full block (2 MB of random spends and outputs) applied on a set of
/// `TABMINER_SCALE_OUTPUTS`: the time to fill the set, and each block's
/// time to apply (`accept`) and to build its template.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_full_block_applies_on_a_large_state() {
    const T: &str = "full-block";
    let n = outputs();
    let blocks = 5;
    let dir = TempDir::new("scale-block");
    let (mut a, filled) = filled_miner("A", &dir, n, blocks);
    report(T, "outputs", n);
    report(T, "fill_secs", format!("{:.1}", filled.as_secs_f64()));
    a.reach(blocks, scaled(n));
    let fills = log_lines(&a, "debug fill: ");
    let totals = log_lines(&a, "  total ");
    assert_eq!(totals.len() as u64, blocks, "a total line per block");
    let mut accepts = Vec::new();
    for (i, (fill, total)) in fills.iter().zip(&totals).enumerate() {
        let accept = secs_after(total, "accept ").unwrap();
        let build = secs_after(total, "build ").unwrap();
        let spends: u64 = fill.split(", ").nth(1).and_then(|s| s.split_whitespace().next()?.parse().ok()).unwrap();
        assert!(spends > 10_000, "block {} is not full: {fill}", i + 1);
        report(T, &format!("block{}_spends", i + 1), spends);
        report(T, &format!("block{}_build_secs", i + 1), format!("{build:.2}"));
        report(T, &format!("block{}_accept_secs", i + 1), format!("{accept:.2}"));
        accepts.push(accept);
    }
    accepts.sort_by(f64::total_cmp);
    let (median, max) = (accepts[accepts.len() / 2], accepts[accepts.len() - 1]);
    report(T, "accept_median_secs", format!("{median:.2}"));
    report(T, "accept_max_secs", format!("{max:.2}"));
    // Only a guard: timings are for reading, runners vary too much to
    // hold them to a number.
    assert!(max < 300.0, "a full block took {max:.1} s to apply");
    let disk = dir_size(&dir.0);
    report(T, "disk_mb", disk / 1_000_000);
    assert!(a.exit(60).success());
}

/// A fresh node fast-syncs a set of `TABMINER_SCALE_OUTPUTS` from one peer:
/// the time from its start to the state installed, and on to the tip.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_fresh_node_fast_syncs_a_large_state() {
    const T: &str = "fast-sync";
    let n = outputs();
    let blocks = 10;
    let (dir_s, dir_c) = (TempDir::new("scale-sync-s"), TempDir::new("scale-sync-c"));
    let (mut s, filled) = filled_miner("S", &dir_s, n, blocks);
    report(T, "outputs", n);
    report(T, "fill_secs", format!("{:.1}", filled.as_secs_f64()));
    s.reach(blocks, scaled(n));
    let n_arg = n.to_string();
    let start = Instant::now();
    let args = [
        "node",
        "--debug-no-validate-proofs",
        "--debug-genesis-outputs",
        &n_arg,
        "--peer",
        &s.addr,
        "--sync-point",
        "4",
    ];
    let mut c = Proc::start_waiting("C", &dir_c.0, &args, &[], scaled(n));
    let genesis = start.elapsed();
    let headers = wait_log(&mut c, "fast sync: block ", 600) + genesis;
    let installed = wait_log(&mut c, "fast sync: installed the state", scaled(n)) + headers;
    assert!(
        log_lines(&c, "validating every block instead").is_empty(),
        "C gave up on fast sync: {:?}",
        log_lines(&c, "fast sync: ")
    );
    c.reach(blocks, 600);
    let synced = start.elapsed();
    assert_eq!(tip(&mut c), tip(&mut s), "C and S on one tip");
    let state = dir_size(&dir_c.0);
    let fetch = installed.saturating_sub(headers).as_secs_f64();
    report(T, "genesis_secs", format!("{:.1}", genesis.as_secs_f64()));
    report(T, "headers_secs", format!("{:.1}", headers.as_secs_f64()));
    report(T, "installed_secs", format!("{:.1}", installed.as_secs_f64()));
    report(T, "tip_secs", format!("{:.1}", synced.as_secs_f64()));
    report(T, "state_fetch_secs", format!("{fetch:.1}"));
    report(T, "disk_mb", state / 1_000_000);
    assert!(c.exit(60).success());
    assert!(s.exit(60).success());
}

/// Bytes under `dir`.
fn dir_size(dir: &std::path::Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            match e.metadata() {
                Ok(m) if m.is_dir() => total += dir_size(&e.path()),
                Ok(m) => total += file_bytes(&m),
                Err(_) => {}
            }
        }
    }
    total
}

/// A file's bytes on disk: LMDB's file is sparse, its length the map's.
#[cfg(unix)]
fn file_bytes(m: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::blocks(m) * 512
}

#[cfg(not(unix))]
fn file_bytes(m: &std::fs::Metadata) -> u64 {
    m.len()
}
