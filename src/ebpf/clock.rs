//! Kernel ktime → wall-clock calibration. The BPF programs stamp
//! `bpf_ktime_get_ns()` (CLOCK_BOOTTIME) at capture; userspace converts to
//! unix nanos with a sampled `CLOCK_REALTIME − CLOCK_BOOTTIME` offset so span
//! timing reflects when the kernel saw the bytes, not when the drain loop got
//! to them. The kernel stays dumb — no clock conversion in BPF.
//!
//! The acceptance test below is the standing definition of the conversion
//! contract. It is owned by the reviewer; any change to its expectations
//! needs reviewer sign-off.

/// A sampled `CLOCK_REALTIME − CLOCK_BOOTTIME` offset for converting kernel
/// `bpf_ktime_get_ns()` stamps to unix nanos. Re-sampled periodically by the
/// capture loop (suspend/resume shifts the two clocks apart).
#[derive(Debug, Clone, Copy)]
pub struct KtimeCalibration {
    offset_ns: i64,
}

impl KtimeCalibration {
    /// Build from an already-known offset (tests and re-sampling).
    pub fn from_offset_ns(offset_ns: i64) -> Self {
        Self { offset_ns }
    }

    /// Convert a kernel `observed_ktime_ns` stamp to unix nanos. Zero means
    /// "the kernel did not stamp" (synthetic tests, old BPF objects) and
    /// returns `None` — the caller falls back to wall-clock now, never to a
    /// garbage timestamp. Out-of-range stamps or sums fall back the same way.
    pub fn convert(&self, observed_ktime_ns: u64) -> Option<i64> {
        if observed_ktime_ns == 0 {
            return None; // unstamped — fall back, never fabricate
        }
        i64::try_from(observed_ktime_ns)
            .ok()?
            .checked_add(self.offset_ns)
    }

    /// Sample the offset afresh: three `(CLOCK_REALTIME, CLOCK_BOOTTIME)`
    /// pairs, medianed — one preempted read pair can skew a sample, but not
    /// the median of three. Returns `None` if a clock read fails; the caller
    /// keeps its previous calibration. Gated to the capture build (its only
    /// consumer) — a plain-Linux build would flag it dead; the conversion
    /// above stays cross-platform.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn sample() -> Option<Self> {
        let mut pairs = [(0i64, 0i64); 3];
        for pair in &mut pairs {
            let realtime = clock_nanos(libc::CLOCK_REALTIME)?;
            let boottime = clock_nanos(libc::CLOCK_BOOTTIME)?;
            *pair = (realtime, boottime);
        }
        Some(Self::from_offset_ns(median_offset_ns(&mut pairs)))
    }
}

/// One clock read as nanos, validated like `runner::monotonic_ns`.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn clock_nanos(clock_id: libc::c_int) -> Option<i64> {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `timestamp` points to writable storage for one `timespec`; the
    // kernel initializes it fully on success and does not retain the pointer.
    if unsafe { libc::clock_gettime(clock_id, timestamp.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the successful call above initialized the complete value.
    let timestamp = unsafe { timestamp.assume_init() };
    // `tv_sec`/`tv_nsec` are already i64 on the shipped Linux targets
    // (x86_64/aarch64), so no conversion — the kernel guarantees
    // `0 <= tv_nsec < 1e9`, but validate rather than trust it.
    let seconds: i64 = timestamp.tv_sec;
    let nanoseconds: i64 = timestamp.tv_nsec;
    if !(0..1_000_000_000).contains(&nanoseconds) {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

/// The offset each sampled `(CLOCK_REALTIME, CLOCK_BOOTTIME)` pair implies,
/// medianed — the middle value wins, so one preempted read pair cannot drag
/// the calibration.
fn median_offset_ns(pairs: &mut [(i64, i64); 3]) -> i64 {
    let mut offsets = [
        pairs[0].0 - pairs[0].1,
        pairs[1].0 - pairs[1].1,
        pairs[2].0 - pairs[2].1,
    ];
    offsets.sort_unstable();
    offsets[1]
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

    #[test]
    fn median_offset_ns_bounds_a_preempted_sample() {
        // Two tight samples + one preempted outlier: the median wins.
        let mut pairs = [
            (1_500, 500),     // offset 1_000
            (9_999_999, 100), // outlier from preemption between the reads
            (1_502, 500),     // offset 1_002
        ];
        assert_eq!(median_offset_ns(&mut pairs), 1_002);
    }

    #[test]
    fn median_offset_ns_orders_negative_offsets() {
        // Boottime ahead of realtime (a backward clock step) is legal and
        // must order correctly as signed values.
        let mut pairs = [
            (0, 1_000), // offset -1_000
            (0, 2_000), // offset -2_000
            (0, 1_500), // offset -1_500
        ];
        assert_eq!(median_offset_ns(&mut pairs), -1_500);
    }
}
