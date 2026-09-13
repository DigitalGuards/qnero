//! What the browser prover costs in linear memory.
//!
//! wasm linear memory grows and never shrinks. That is the whole measurement
//! method: the size of the memory after a call is the high-water mark of every
//! allocation the call made, and it stays that size for the life of the
//! worker. So a sample taken after each phase is the peak up to that phase,
//! with no allocator hook and no sampling thread.
//!
//! `performance.measureUserAgentSpecificMemory()` is the other way to ask, and
//! it is available in the harness: `www/server.mjs` sends COOP and COEP on
//! every response, so the page is cross-origin isolated and a later threads
//! experiment needs no different server. `byteLength` is used anyway, because
//! it is the same number on both sides of the wasm boundary, it costs no
//! permission and no await, and linear memory never shrinks, so a sample after
//! a phase already is the high-water mark of everything up to it.

use core::sync::atomic::{AtomicUsize, Ordering};

/// One wasm page.
pub const PAGE_BYTES: usize = 64 * 1024;

static PEAK: AtomicUsize = AtomicUsize::new(0);
static LAST_CALL_GROWTH: AtomicUsize = AtomicUsize::new(0);

/// Linear memory currently reserved by this module, in bytes.
///
/// Zero on a native build, where there is no linear memory to report and the
/// process-wide RSS is the number that means anything. `/usr/bin/time -v` is
/// how `docs/BENCH.md` measures that one.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub fn linear_memory_bytes() -> usize {
    core::arch::wasm32::memory_size::<0>() * PAGE_BYTES
}

/// See the wasm arm.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub fn linear_memory_bytes() -> usize {
    0
}

/// Sample linear memory and fold it into the process peak.
pub fn sample() -> usize {
    let now = linear_memory_bytes();
    PEAK.fetch_max(now, Ordering::Relaxed);
    now
}

/// The largest sample taken since the module was instantiated.
pub fn peak_bytes() -> usize {
    PEAK.load(Ordering::Relaxed).max(linear_memory_bytes())
}

/// What one call cost, measured against the memory it found on entry.
///
/// There is no per-call peak to report. `PEAK` is a module-wide high-water
/// mark and linear memory never shrinks, so once a circuit is resident every
/// later call reads its memory back. The two numbers here are the two honest
/// ones: what the whole module has ever held, and how much this call grew it.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct CallMemory {
    /// The module's high-water mark since it was instantiated. It counts every
    /// circuit already built, so it sizes a worker rather than a call.
    pub peak_bytes_since_init: usize,
    /// How much this call added on top of what it found. A call that fits
    /// inside memory an earlier call already grew into reports zero, so this
    /// is a lower bound on what the same call needs in a fresh worker. The
    /// harness answers that upper question by running a call on its own, which
    /// is what `run.mjs --zk-only` is for.
    pub growth_bytes: usize,
}

/// Close out one call: fold a final sample in, and record what it grew.
///
/// `entry_bytes` is the [`MemorySpan::start`] sample taken when the call began.
pub fn record_call(entry_bytes: usize) -> CallMemory {
    let peak_bytes_since_init = peak_bytes();
    let growth_bytes = peak_bytes_since_init.saturating_sub(entry_bytes);
    LAST_CALL_GROWTH.store(growth_bytes, Ordering::Relaxed);
    CallMemory {
        peak_bytes_since_init,
        growth_bytes,
    }
}

/// How much linear memory the last proving call added to what it found.
pub fn last_call_growth_bytes() -> usize {
    LAST_CALL_GROWTH.load(Ordering::Relaxed)
}

/// Memory before and after one phase, with the peak it left behind.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct MemorySpan {
    pub before_bytes: usize,
    pub after_bytes: usize,
    pub peak_bytes: usize,
}

impl MemorySpan {
    pub fn start() -> usize {
        sample()
    }

    pub fn end(before_bytes: usize) -> Self {
        let after_bytes = sample();
        Self {
            before_bytes,
            after_bytes,
            peak_bytes: peak_bytes(),
        }
    }
}
