//! What is left of the admin surface, which is the argument that there is none.
//!
//! This directory was `governance/`, and it held the tech collective's 1 810
//! lines and the fast-upgrade track's 252. Both went with the lane. The two
//! files here cover the pallets that kept a privileged-looking call: the
//! treasury, whose `set_treasury_account` has no `RuntimeCall` variant any
//! more, and vesting, whose three admin calls are refused by the call filter
//! and by an `AdminOrigin` that accepts nobody.
pub mod treasury;
pub mod vesting;
