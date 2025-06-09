#![cfg_attr(not(feature = "user"), no_std)]
#![cfg_attr(not(feature = "user"), feature(int_log))]
mod rule_store;

pub use rule_store::{Action, GENERIC_PROTO, RuleStore};

#[cfg(feature = "user")]
pub use rule_store::RuleStoreError;
use strum_macros::EnumCount;

#[repr(u8)]
#[derive(Clone, Copy, EnumCount)]
pub enum ConfigOpt {
    DefaultAction = 0,
}

// Safety ConfigOpt is repr(u8)
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConfigOpt {}
