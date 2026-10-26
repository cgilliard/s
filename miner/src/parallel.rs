//! Minimal data parallelism over scoped threads.
//!
//! Work is split into contiguous ranges, one per thread, so the helpers
//! suit loops whose iterations cost about the same. The thread count is
//! `available_parallelism`, overridable with the `TABMINER_THREADS`
//! environment variable; small inputs run on the calling thread.

use std::sync::OnceLock;

/// Number of worker threads.
pub fn threads() -> usize {
    static THREADS: OnceLock<usize> = OnceLock::new();
    *THREADS.get_or_init(|| {
        std::env::var("TABMINER_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
    })
}

/// Below this many items a loop runs serially.
const MIN_PARALLEL: usize = 1024;

/// Splits `0..n` into at most `threads()` contiguous ranges.
fn ranges(n: usize, min_per_thread: usize) -> Vec<std::ops::Range<usize>> {
    let t = threads().min(n / min_per_thread.max(1)).max(1);
    let per = n.div_ceil(t);
    (0..t).map(|k| (k * per).min(n)..((k + 1) * per).min(n)).filter(|r| !r.is_empty()).collect()
}

/// `(0..n).map(f)` evaluated in parallel.
pub fn par_map<T: Send, F: Fn(usize) -> T + Sync>(n: usize, f: F) -> Vec<T> {
    par_map_min(n, MIN_PARALLEL, f)
}

/// As [`par_map`], but with an explicit serial threshold: parallel only
/// when at least `min_per_thread` items fall to each thread.
pub fn par_map_min<T: Send, F: Fn(usize) -> T + Sync>(n: usize, min_per_thread: usize, f: F) -> Vec<T> {
    let ranges = ranges(n, min_per_thread);
    if ranges.len() <= 1 {
        return (0..n).map(f).collect();
    }
    let f = &f;
    let parts: Vec<Vec<T>> = std::thread::scope(|s| {
        let handles: Vec<_> = ranges.into_iter().map(|r| s.spawn(move || r.map(f).collect::<Vec<T>>())).collect();
        handles.into_iter().map(|h| h.join().expect("worker panicked")).collect()
    });
    let mut out = Vec::with_capacity(n);
    for p in parts {
        out.extend(p);
    }
    out
}

/// Runs `f(chunk_index, chunk)` over `data.chunks_mut(chunk)` in parallel.
pub fn par_chunks_mut<T: Send, F: Fn(usize, &mut [T]) + Sync>(data: &mut [T], chunk: usize, f: F) {
    assert!(chunk > 0);
    let chunks: Vec<(usize, &mut [T])> = data.chunks_mut(chunk).enumerate().collect();
    let n = chunks.len();
    let ranges = ranges(n, 1);
    if ranges.len() <= 1 {
        for (i, c) in chunks {
            f(i, c);
        }
        return;
    }
    let f = &f;
    let mut chunks = chunks.into_iter();
    std::thread::scope(|s| {
        for r in ranges {
            let mine: Vec<(usize, &mut [T])> = chunks.by_ref().take(r.len()).collect();
            s.spawn(move || {
                for (i, c) in mine {
                    f(i, c);
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn par_map_matches_serial() {
        for n in [0, 1, 5, 1000, 4096, 100_003] {
            let got = par_map_min(n, 1, |i| i * i + 1);
            let want: Vec<usize> = (0..n).map(|i| i * i + 1).collect();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn par_chunks_mut_touches_every_element_once() {
        let mut v = vec![0u32; 10_007];
        par_chunks_mut(&mut v, 100, |i, c| {
            for (k, x) in c.iter_mut().enumerate() {
                *x += (i * 100 + k) as u32;
            }
        });
        assert!(v.iter().enumerate().all(|(i, x)| *x == i as u32));
    }
}
