#![allow(unexpected_cfgs)]

#[cfg(coverage)]
use anyhow::Result;

#[cfg(coverage)]
pub fn run_conformance(_quick: bool) -> Result<()> {
    Ok(())
}

#[cfg(not(coverage))]
include!("conform_real.rs");
