#![warn(clippy::dbg_macro)]
#![recursion_limit = "2048"] // Increase for deeply nested Prisma+Axum types (circular Series<->Media relations)
#![type_length_limit = "33554432"] // Increase limit for complex Prisma queries (32MB)

pub mod config;
mod errors;
mod filter;
mod http_server;
pub mod middleware;
mod routers;
mod secure;
mod utils;

// Re-export prisma module so prisma-client-rust select!/include! macros expand correctly in this crate
pub use stump_core::prisma;

pub use http_server::{bootstrap_http_server_config, run_http_server};
