#[cfg(target_arch="x86_64")]
mod x86;

#[cfg(target_arch="x86_64")]
pub use x86::*;

#[cfg(target_arch="aarch64")]
mod aarch64;

#[cfg(target_arch="aarch64")]
pub use aarch64::*;

pub const fn regs_count() -> usize {
    SAMPLE_REGS_USER.count_ones() as usize
}