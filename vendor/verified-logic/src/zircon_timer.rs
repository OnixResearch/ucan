//! Verified Zircon timer lifecycle.
//!
//! Timers are idle, armed for a deadline, or signaled. Once signaled,
//! ZX_TIMER_SIGNALED persists until cancel or reset.

use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::deadline_queue::is_earlier_spec;
use crate::signal::signal_add;

verus! {

pub const ZX_TIMER_IDLE: u8 = 0u8;
pub const ZX_TIMER_ARMED: u8 = 1u8;
pub const ZX_TIMER_SIGNALED_STATE: u8 = 2u8;
pub const ZX_TIMER_SIGNALED: u64 = 1u64 << 0;

pub struct ZirconTimer {
    pub koid: u64,
    pub state: u8,
    pub deadline: u64,
}

impl ZirconTimer {
    pub open spec fn wf(&self) -> bool {
        self.state == ZX_TIMER_IDLE || self.state == ZX_TIMER_ARMED || self.state == ZX_TIMER_SIGNALED_STATE
    }
}

// r[depends zircon-timer.lifecycle]
pub open spec fn timer_signaled_spec(timer: ZirconTimer) -> bool {
    timer.state == ZX_TIMER_SIGNALED_STATE
}

// r[impl zircon-timer.lifecycle]
pub fn timer_signaled(timer: &ZirconTimer) -> (result: bool)
    requires timer.wf()
    ensures result == timer_signaled_spec(*timer)
{
    timer.state == ZX_TIMER_SIGNALED_STATE
}

// r[impl zircon-timer.lifecycle]
pub fn new_timer(koid: u64) -> (result: ZirconTimer)
    ensures result.wf(), result.koid == koid, result.state == ZX_TIMER_IDLE
{
    ZirconTimer { koid, state: ZX_TIMER_IDLE, deadline: 0 }
}

// r[impl zircon-timer.lifecycle]
pub fn set_timer(timer: &ZirconTimer, deadline: u64) -> (result: ZirconTimer)
    requires timer.wf()
    ensures result.wf(), result.koid == timer.koid, result.state == ZX_TIMER_ARMED, result.deadline == deadline
{
    ZirconTimer { koid: timer.koid, state: ZX_TIMER_ARMED, deadline }
}

// r[impl zircon-timer.lifecycle]
pub fn cancel_timer(timer: &ZirconTimer) -> (result: ZirconTimer)
    requires timer.wf()
    ensures result.wf(), result.koid == timer.koid, result.state == ZX_TIMER_IDLE
{
    ZirconTimer { koid: timer.koid, state: ZX_TIMER_IDLE, deadline: 0 }
}

// r[impl zircon-timer.lifecycle]
pub fn reset_timer(timer: &ZirconTimer, deadline: u64) -> (result: ZirconTimer)
    requires timer.wf()
    ensures result.wf(), result.koid == timer.koid, result.state == ZX_TIMER_ARMED, result.deadline == deadline
{
    ZirconTimer { koid: timer.koid, state: ZX_TIMER_ARMED, deadline }
}

// r[impl zircon-timer.lifecycle]
pub fn advance_time(timer: ZirconTimer, now: u64) -> (result: ZirconTimer)
    requires timer.wf()
    ensures
        result.wf(),
        result.koid == timer.koid,
        timer.state == ZX_TIMER_SIGNALED_STATE ==> result.state == ZX_TIMER_SIGNALED_STATE,
        timer.state == ZX_TIMER_ARMED && now >= timer.deadline ==> result.state == ZX_TIMER_SIGNALED_STATE,
        timer.state == ZX_TIMER_ARMED && now < timer.deadline ==> result.state == ZX_TIMER_ARMED,
{
    if timer.state == ZX_TIMER_SIGNALED_STATE {
        timer
    } else if timer.state == ZX_TIMER_ARMED && now >= timer.deadline {
        ZirconTimer { koid: timer.koid, state: ZX_TIMER_SIGNALED_STATE, deadline: timer.deadline }
    } else {
        timer
    }
}

// r[depends zircon-timer.lifecycle]
pub open spec fn timer_signals_spec(timer: ZirconTimer) -> u64
    recommends timer.wf()
{
    if timer_signaled_spec(timer) { ZX_TIMER_SIGNALED } else { 0 }
}

// r[impl zircon-timer.lifecycle]
pub fn timer_signals(timer: &ZirconTimer) -> (result: u64)
    requires timer.wf()
    ensures result == timer_signals_spec(*timer)
{
    if timer.state == ZX_TIMER_SIGNALED_STATE {
        ZX_TIMER_SIGNALED
    } else {
        0
    }
}

// r[verify zircon-timer.lifecycle]
proof fn signaled_persists(timer: ZirconTimer, _now: u64)
    requires timer.wf(), timer.state == ZX_TIMER_SIGNALED_STATE
    ensures timer_signaled_spec(timer)
{}

// r[verify zircon-timer.lifecycle]
proof fn cancel_clears_signal(timer: ZirconTimer)
    requires timer.wf()
    ensures timer_signals_spec(ZirconTimer { koid: timer.koid, state: ZX_TIMER_IDLE, deadline: 0 }) == 0
{}

// r[verify zircon-timer.lifecycle]
proof fn reset_clears_and_rearms(timer: ZirconTimer, deadline: u64)
    requires timer.wf()
    ensures (ZirconTimer { koid: timer.koid, state: ZX_TIMER_ARMED, deadline }).state == ZX_TIMER_ARMED,
            timer_signals_spec(ZirconTimer { koid: timer.koid, state: ZX_TIMER_ARMED, deadline }) == 0
{}

// r[verify zircon-timer.lifecycle]
proof fn deadline_order_respected(a: ZirconTimer, b: ZirconTimer, now: u64)
    requires a.wf(), b.wf(), a.state == ZX_TIMER_ARMED, b.state == ZX_TIMER_ARMED, is_earlier_spec(a.deadline, b.deadline), now >= b.deadline
    ensures now >= a.deadline
{}

} // verus!

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // r[verify zircon-timer.lifecycle]
    #[test]
    fn test_timer_lifecycle() {
        let t = new_timer(1);
        let t = set_timer(&t, 10);
        let t = advance_time(t, 9);
        assert_eq!(timer_signals(&t), 0);
        let t = advance_time(t, 10);
        assert_eq!(timer_signals(&t), ZX_TIMER_SIGNALED);
        let t = cancel_timer(&t);
        assert_eq!(timer_signals(&t), 0);
    }

    // r[verify zircon-timer.lifecycle]
    #[test]
    fn test_reset_rearms() {
        let t0 = new_timer(1);
        let t = set_timer(&t0, 5);
        let t = advance_time(t, 5);
        assert_eq!(timer_signals(&t), ZX_TIMER_SIGNALED);
        let t = reset_timer(&t, 9);
        assert_eq!(timer_signals(&t), 0);
        let t = advance_time(t, 9);
        assert_eq!(timer_signals(&t), ZX_TIMER_SIGNALED);
    }

    proptest! {
        // r[verify zircon-timer.lifecycle]
        #[test]
        fn prop_signaled_persists(deadline: u64, now: u64) {
            let t = ZirconTimer { koid: 1, state: ZX_TIMER_SIGNALED_STATE, deadline };
            prop_assert_eq!(advance_time(t, now).state, ZX_TIMER_SIGNALED_STATE);
        }

        // r[verify zircon-timer.lifecycle]
        #[test]
        fn prop_deadline_pass_fires(deadline: u64, extra in 0u64..1000) {
            let now = deadline.saturating_add(extra);
            let t0 = new_timer(1);
            let t = set_timer(&t0, deadline);
            prop_assert_eq!(advance_time(t, now).state, ZX_TIMER_SIGNALED_STATE);
        }
    }
}
