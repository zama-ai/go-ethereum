#![cfg_attr(feature = "backtraces", feature(backtrace))]
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::missing_safety_doc)]
pub mod api;
mod version;
pub mod memory;
pub(crate) mod error;
pub(crate) mod keys;

//pub use api;
pub use version::version_str;