// identity\benches\benchmark.rs
/// Purpose: This module sets up and organizes cryptographic benchmarks
/// using the Criterion benchmarking framework. It includes tests for keypair 
/// generation, signing, verification, serialization, and throughput performance.


/// Declare the `pki_benchmark` module and its submodules.
/// Each submodule corresponds to a specific benchmarking functionality.
mod pki_benchmark { 
    /// Benchmark for keypair generation across different cryptographic algorithms.
    pub mod keypair_generation_benchmark;

    /// Benchmark for measuring signing and verification times.
    pub mod keypair_verify_sign_benchmark;

    /// Benchmark for serialization and deserialization of keypairs.
    pub mod keypair_serialization_benchmark;

    /// Benchmark for measuring throughput in terms of signing and verification operations per second.
    pub mod keypair_throughput_benchmark;

    /// Benchmark for measuing Keypair exchange rates
    pub mod keypair_exchange_benchmark;
}

// Use `criterion_main` to define the entry point for the benchmarks.
// This macro initializes the benchmark tests based on the selected feature flags.
criterion::criterion_main!(
    // Runs the keypair generation benchmark.
    pki_benchmark::keypair_generation_benchmark::crypto_benchmarks,

    // Runs the signing and verification benchmark.
    pki_benchmark::keypair_verify_sign_benchmark::crypto_benchmarks,

    // Runs the serialization and deserialization benchmark.
    pki_benchmark::keypair_serialization_benchmark::crypto_benchmarks,

    // Runs the throughput benchmark (sign/verify operations per second).
    pki_benchmark::keypair_throughput_benchmark::crypto_benchmarks,

    // Run the Key Exchange benchmark
    pki_benchmark::keypair_exchange_benchmark::crypto_benchmarks,
);
