//! One monotonic clock, chosen per target.
//!
//! `std::time::Instant::now()` panics on `wasm32-unknown-unknown`: the target
//! has no clock and std's shim aborts rather than returning a wrong answer.
//! `performance.now()` is the browser's monotonic millisecond clock and is
//! defined in a Worker as well as on a page, which matters because every
//! proving call here belongs in a Worker.
//!
//! Note what is NOT a problem: qp-plonky2's own `Instant` uses sit behind its
//! `timing` feature (which pulls `web-time`) and behind `#[cfg(test)]`. This
//! workspace takes qp-plonky2 with `default-features = false` plus `std`, so
//! `timing` is off and nothing in the proving path reads a clock.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod imp {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = performance, js_name = now)]
        fn performance_now() -> f64;
    }

    pub fn now_ms() -> f64 {
        performance_now()
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod imp {
    use std::sync::OnceLock;
    use std::time::Instant;

    fn origin() -> Instant {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        *ORIGIN.get_or_init(Instant::now)
    }

    pub fn now_ms() -> f64 {
        origin().elapsed().as_secs_f64() * 1000.0
    }
}

pub use imp::now_ms;

/// Time one closure, in milliseconds.
pub fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let started = now_ms();
    let value = f();
    (value, now_ms() - started)
}
