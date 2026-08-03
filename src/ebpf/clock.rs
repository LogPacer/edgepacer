//! Kernel ktime → wall-clock calibration. The BPF programs stamp
//! `bpf_ktime_get_ns()` (CLOCK_BOOTTIME) at capture; userspace converts to
//! unix nanos with a sampled `CLOCK_REALTIME − CLOCK_BOOTTIME` offset so span
//! timing reflects when the kernel saw the bytes, not when the drain loop got
//! to them. The kernel stays dumb — no clock conversion in BPF.
//!
//! The `#[ignore]`d acceptance test below is the standing definition of the
//! conversion contract. It is owned by the reviewer — implement until it
//! passes with the `#[ignore]` attribute removed; any change to its
//! expectations needs reviewer sign-off.

/// A sampled `CLOCK_REALTIME − CLOCK_BOOTTIME` offset for converting kernel
/// `bpf_ktime_get_ns()` stamps to unix nanos. Re-sampled periodically by the
/// capture loop (suspend/resume shifts the two clocks apart).
#[derive(Debug, Clone, Copy)]
pub struct KtimeCalibration {
    offset_ns: i64,
}

impl KtimeCalibration {
    /// Build from an already-known offset (tests and re-sampling).
    #[allow(dead_code)] // wired into capture.rs later in this slice
    pub fn from_offset_ns(offset_ns: i64) -> Self {
        Self { offset_ns }
    }

    /// Convert a kernel `observed_ktime_ns` stamp to unix nanos. Zero means
    /// "the kernel did not stamp" (synthetic tests, old BPF objects) and
    /// returns `None` — the caller falls back to wall-clock now, never to a
    /// garbage timestamp.
    #[allow(dead_code)] // wired into capture.rs later in this slice
    pub fn convert(&self, observed_ktime_ns: u64) -> Option<i64> {
        // Slice 3 stub: the acceptance test below defines the contract and
        // stays #[ignore]d red until this is implemented.
        let _ = (self.offset_ns, observed_ktime_ns);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conversion contract in one self-controlling test: a stamped ktime
    /// converts as `ktime + offset` (offsets can be negative — boottime can
    /// exceed realtime after clock steps), and a zero stamp is `None`, the
    /// explicit fall-back-to-wall-clock signal. The positive rows keep the
    /// zero row from passing vacuously against a convert that always bails.
    #[test]
    #[ignore = "Slice 3 acceptance — implement KtimeCalibration::convert, then remove this ignore"]
    fn stamped_ktime_converts_with_offset_and_zero_falls_back() {
        let cal = KtimeCalibration::from_offset_ns(1_000_000_000);
        assert_eq!(
            cal.convert(5_000),
            Some(1_000_005_000),
            "unix_nano = ktime + offset"
        );

        let negative = KtimeCalibration::from_offset_ns(-2_000);
        assert_eq!(
            negative.convert(5_000),
            Some(3_000),
            "negative offsets are legal"
        );

        assert_eq!(
            cal.convert(0),
            None,
            "zero ktime means unstamped — fall back, never fabricate"
        );
    }
}
