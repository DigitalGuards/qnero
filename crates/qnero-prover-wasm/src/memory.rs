//! What the browser prover costs in linear memory.
//!
//! wasm linear memory grows and never shrinks. That is the whole measurement
//! method: the size of the memory after a call is the high-water mark of every
//! allocation the call made, and it stays that size for the life of the
//! worker. So a sample taken after each phase is the peak up to that phase,
//! with no allocator hook and no sampling thread.
//!
//! `performance.measureUserAgentSpecificMemory()` is the other way to ask, and
//! it needs cross-origin isolation, which this milestone deliberately does not
//! take (see the threads note in `docs/DESIGN.md` section 8). The JS side of
//! the harness reads `WebAssembly.Memory.prototype.buffer.byteLength` instead,
//! which is the same number this module reports, from the other side of the
//! boundary.

use core::sync::atomic::{AtomicUsize, Ordering};

/// One wasm page.
pub const PAGE_BYTES: usize = 64 * 1024;

static PEAK: AtomicUsize = AtomicUsize::new(0);
static LAST_CALL_PEAK: AtomicUsize = AtomicUsize::new(0);

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

/// Record the peak one call reached, and return it.
pub fn record_call_peak() -> usize {
    let peak = peak_bytes();
    LAST_CALL_PEAK.store(peak, Ordering::Relaxed);
    peak
}

/// The peak the last proving call reached.
pub fn last_call_peak_bytes() -> usize {
    LAST_CALL_PEAK.load(Ordering::Relaxed)
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
