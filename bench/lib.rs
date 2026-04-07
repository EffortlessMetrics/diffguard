//! diffguard-bench: Performance benchmark infrastructure
//!
//! This crate provides benchmark infrastructure for measuring diffguard's
//! performance across several categories:
//!
//! - **Parsing**: Diff parsing throughput for various file sizes
//! - **Evaluation**: Rule evaluation latency at various rule counts
//! - **Rendering**: Output rendering time for various finding counts
//! - **Preprocessing**: Comment/string masking at various densities
//!
//! ## Running Benchmarks
//!
//! ```bash
//! # Run all benchmarks
//! cargo bench --workspace
//!
//! # Run with HTML report
//! cargo bench --workspace -- --html
//!
//! # Run specific benchmark
//! cargo bench -p diffguard-bench -- parsing
//! ```
//!
//! ## Architecture
//!
//! Benchmarks use [criterion](https://crates.io/crates/criterion) for statistical
//! analysis and comparison reporting. All inputs are synthetic (generated in-memory)
//! to ensure reproducibility and avoid I/O variance.

pub mod fixtures;
