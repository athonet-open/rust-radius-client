#![deny(warnings)]
#![deny(missing_docs)]

//! # RADIUS client
//!
//! Full Rust library to communicate with a RADIUS server
//! Inspired by pyrad https://github.com/wichert/pyrad/

extern crate rand;
extern crate crypto;
extern crate mio;

/// Client entities
pub mod client;
/// Protocol entities
pub mod radius;
