#![allow(dead_code)] // Scaffolding — stubs will be wired incrementally

pub mod api;
pub mod cdc;
pub mod cli;
pub mod config;
pub mod crypto;
#[cfg(feature = "mesh-broker-client")]
pub mod mesh_ingest;
pub mod storage;
pub mod tenant;

#[cfg(feature = "loadtest")]
pub mod loadtest;
