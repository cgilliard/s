//! The harness the binary's tests share: `tabminer` processes on
//! loopback, on a `--network dev` chain of their own, driven through
//! their prompts.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

/// A data directory under the system's temporary directory, removed when
/// dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("tabminer-bin-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    /// Removes the directory, unless the test failed: then it is kept,
    /// with the logs, for a look.
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("kept {}", self.0.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// One running `tabminer`, its stdout and stderr read line by line.
pub struct Proc {
    pub name: &'static str,
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    pub lines: Receiver<String>,
    pub seen: Vec<String>,
    pub data: PathBuf,
    /// Where it listens, from its "listening on" line.
    pub addr: String,
}

impl Proc {
    /// Starts one on a port of the system's choosing, and waits until it
    /// listens.
    pub fn start(name: &'static str, data: &Path, args: &[&str]) -> Proc {
        Proc::start_with(name, data, args, &[])
    }

    /// [`Proc::start`] with `env` set too.
    pub fn start_with(name: &'static str, data: &Path, args: &[&str], env: &[(&str, &str)]) -> Proc {
        Proc::start_waiting(name, data, args, env, 60)
    }

    /// [`Proc::start_with`], waiting up to `secs` for it to listen (a node
    /// filling a large state first takes long).
    pub fn start_waiting(name: &'static str, data: &Path, args: &[&str], env: &[(&str, &str)], secs: u64) -> Proc {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tabminer"))
            .args(args)
            .envs(env.iter().copied())
            .args(["--network", "dev", "--no-seeds", "--listen", "127.0.0.1:0", "--data"])
            .arg(data)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, lines) = channel();
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let _ = tx2.send(format!("stderr: {line}"));
            }
        });
        let stdin = child.stdin.take();
        let mut p = Proc { name, child, stdin, lines, seen: Vec::new(), data: data.to_path_buf(), addr: String::new() };
        let line = p.expect("listening line", secs, |l| l.starts_with("listening on "));
        p.addr = line["listening on ".len()..].split(';').next().unwrap().to_string();
        p
    }

    pub fn send(&mut self, command: &str) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{command}").unwrap();
        stdin.flush().unwrap();
    }

    /// The next line meeting `want` within `wait`, the prompt's "> "
    /// taken off; `None` once `wait` has passed.
    pub fn next_matching(&mut self, want: &dyn Fn(&str) -> bool, wait: Duration) -> Option<String> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    let line = line.trim_start_matches("> ").to_string();
                    if want(&line) {
                        return Some(line);
                    }
                }
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(left.min(Duration::from_millis(100)));
                    if Instant::now() >= deadline {
                        return None;
                    }
                }
            }
        }
    }

    /// Waits up to `secs` for a line meeting `want`.
    pub fn expect(&mut self, what: &str, secs: u64, want: impl Fn(&str) -> bool) -> String {
        match self.next_matching(&want, guard(secs)) {
            Some(line) => line,
            None => panic!("{}: no {what} within {secs} s", self.name),
        }
    }

    /// Runs `command` once a second until a line of its answer meets
    /// `want`, for up to `secs`.
    pub fn poll(&mut self, command: &str, what: &str, secs: u64, want: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + guard(secs);
        while Instant::now() < deadline {
            self.send(command);
            if let Some(line) = self.next_matching(&want, Duration::from_secs(1)) {
                return line;
            }
        }
        panic!("{}: `{command}` never showed {what} within {secs} s", self.name);
    }

    /// Writes `exit` and waits up to `secs` for the process to end.
    pub fn exit(&mut self, secs: u64) -> std::process::ExitStatus {
        self.send("exit");
        let deadline = Instant::now() + guard(secs);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "{}: still running {secs} s after exit", self.name);
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits up to `secs` for the process to end by itself, and that it
    /// failed.
    pub fn dies(&mut self, secs: u64) {
        let deadline = Instant::now() + guard(secs);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(!status.success(), "{}: ended cleanly", self.name);
                return;
            }
            assert!(Instant::now() < deadline, "{}: still running after {secs} s", self.name);
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits up to `secs` for a line of its log containing `text`.
    pub fn expect_log(&mut self, text: &str, secs: u64) {
        let deadline = Instant::now() + guard(secs);
        loop {
            let log = std::fs::read_to_string(self.data.join("tabminer.log")).unwrap_or_default();
            if log.contains(text) {
                return;
            }
            assert!(Instant::now() < deadline, "{}: no `{text}` in its log within {secs} s", self.name);
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Sends `amount` to `to` (an address or @name), trying again while
    /// the lookup or the send fails, for up to `secs`.
    pub fn pay(&mut self, amount: &str, to: &str, secs: u64) {
        let deadline = Instant::now() + guard(secs);
        loop {
            self.send(&format!("send {amount} {to}"));
            let line = self.expect("the send's outcome", 60, |l| {
                (l.starts_with("slate ") && l.contains("sent to")) || l.starts_with("error:")
            });
            if line.starts_with("slate ") {
                return;
            }
            assert!(Instant::now() < deadline, "{}: `send {amount} {to}` kept failing: {line}", self.name);
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// Waits up to `secs` for the chain to reach `at_least`.
    pub fn reach(&mut self, at_least: u64, secs: u64) {
        let deadline = Instant::now() + guard(secs);
        while self.height() < at_least {
            assert!(Instant::now() < deadline, "{}: height {at_least} never came", self.name);
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Waits up to `secs` for the wallet to hold nothing: no outputs, none
    /// confirmed, none pending.
    pub fn holds_nothing(&mut self, secs: u64) {
        self.poll("outputs", "no outputs", secs, |l| l == "no outputs");
        self.send("balance");
        let confirmed = self.expect("the confirmed line", 10, |l| l.starts_with("confirmed"));
        let pending = self.expect("the pending line", 10, |l| l.starts_with("pending"));
        assert_eq!(amount(&confirmed, "confirmed"), Some(0.0), "{}: {confirmed}", self.name);
        assert_eq!(amount(&pending, "pending"), Some(0.0), "{}: {pending}", self.name);
    }

    /// The chain's height, from `status`.
    pub fn height(&mut self) -> u64 {
        self.send("status");
        let line = self.expect("the tip", 10, |l| l.starts_with("tip      height "));
        line["tip      height ".len()..].split_whitespace().next().unwrap().parse().unwrap()
    }

    /// The recovery phrase it printed when it made its wallet.
    pub fn phrase(&self) -> String {
        let words = |l: &str| {
            l.split_whitespace().count() == 12 && l.trim().chars().all(|c| c == ' ' || c.is_ascii_lowercase())
        };
        self.seen
            .iter()
            .find(|l| words(l))
            .unwrap_or_else(|| panic!("{}: printed no phrase", self.name))
            .trim()
            .to_string()
    }

    /// The wallet's address, from `address`.
    pub fn address(&mut self) -> String {
        self.send("address");
        self.expect("address", 10, |l| l.starts_with("tab1"))
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            while let Ok(line) = self.lines.try_recv() {
                self.seen.push(line);
            }
            eprintln!("---- {} output ----", self.name);
            for line in &self.seen {
                eprintln!("{line}");
            }
            if let Ok(log) = std::fs::read_to_string(self.data.join("tabminer.log")) {
                eprintln!("---- {} log (last 60 lines) ----", self.name);
                let lines: Vec<&str> = log.lines().collect();
                for line in &lines[lines.len().saturating_sub(60)..] {
                    eprintln!("{line}");
                }
            }
        }
    }
}

/// How long a step may take before the test calls it stuck: generous, and
/// longer in debug builds.
pub fn guard(secs: u64) -> Duration {
    Duration::from_secs(if cfg!(debug_assertions) { 3 * secs } else { secs })
}

/// A coin amount line such as `confirmed 12.50000000  spendable`: the
/// amount.
pub fn amount(line: &str, label: &str) -> Option<f64> {
    line.strip_prefix(label)?.split_whitespace().next()?.parse().ok()
}
