//! Library code for the sshx command-line client application.
//!
//! This crate does not forbid use of unsafe code because it needs to interact
//! with operating-system APIs to access pseudoterminal (PTY) devices.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod controller;
pub mod encrypt;
pub mod p2p;
pub mod p2p_events;
pub mod p2p_network;
pub mod p2p_terminal_sync;
pub mod runner;
pub mod session_persistence;
pub mod string_compressor;
pub mod terminal;
