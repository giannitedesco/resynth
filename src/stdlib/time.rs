use crate::libapi::{FuncDef, Module};
use crate::sym::Symbol;
use crate::val::Val;

const HZ: u64 = 1_000_000_000;
const KHZ: u64 = HZ / 1000;
const MHZ: u64 = KHZ / 1000;

static JUMP_SECS: FuncDef = func!(
    /// Advance the pcap timestamp clock by some number of seconds
    resynth fn jump_seconds(
        /// Number of seconds to advance the clock
        seconds: U32,
        =>
        =>
        Void
    ) -> TimeJump
    |mut args| {
        let secs: u32 = args.next().into();

        Ok(Val::TimeJump((secs as u64) * HZ))
    }
);

static JUMP_MILLIS: FuncDef = func!(
    /// Advance the pcap timestamp clock by some number of milliseconds
    resynth fn jump_millis(
        /// Number of milliseconds to advance the clock
        ms: U64,
        =>
        =>
        Void
    ) -> TimeJump
    |mut args| {
        let ms: u64 = args.next().into();

        Ok(Val::TimeJump(ms * KHZ))
    }
);

static JUMP_MICROS: FuncDef = func!(
    /// Advance the pcap timestamp clock by some number of microseconds
    resynth fn jump_micros(
        /// Number of microseconds to advance the clock
        us: U64,
        =>
        =>
        Void
    ) -> TimeJump
    |mut args| {
        let us: u64 = args.next().into();

        Ok(Val::TimeJump(us * MHZ))
    }
);

static JUMP_NANOS: FuncDef = func!(
    /// Advance the pcap timestamp clock by some number of nanoseconds
    resynth fn jump_nanos(
        /// Number of nanoseconds to advance the clock
        ns: U64,
        =>
        =>
        Void
    ) -> TimeJump
    |mut args| {
        let ns: u64 = args.next().into();

        Ok(Val::TimeJump(ns))
    }
);

pub const MODULE: Module = module! {
    /// # Time Manipulation
    ///
    /// Functions to control packet timestamps and introduce time offsets in captures.
    resynth mod time {
        jump_seconds => Symbol::Func(&JUMP_SECS),
        jump_millis => Symbol::Func(&JUMP_MILLIS),
        jump_micros => Symbol::Func(&JUMP_MICROS),
        jump_nanos => Symbol::Func(&JUMP_NANOS),
    }
};
