// identity/benches/pki_benchmark/key_exchange_benchmark.rs
use criterion::{Criterion, criterion_group, criterion_main};
use std::env;
use std::fs::OpenOptions;
use std::io::{Write, BufReader, BufRead};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant};
use sysinfo::System;
use std::fmt::Debug;

use identity::{KeyExchange, PKITraits};

#[cfg(feature = "pki_rsa")]
use identity::RSAkeyPair;
#[cfg(feature = "kyber")]
use identity::KyberKeyPair;

// -- For “no-op” stubs, we still import them so code compiles when features are on:
#[cfg(feature = "ecdsa")]
use identity::ECDSAKeyPair;

#[cfg(feature = "ed25519")]
use identity::Ed25519KeyPair;

#[cfg(feature = "secp256k1")]
use identity::SECP256K1KeyPair;

const ITERATIONS: usize = 10;

fn get_benchmark_path() -> PathBuf {
    let mut path = env::current_dir().expect("Failed to get current directory");
    path.pop();
    path.push("benches");
    path
}

fn ensure_headers(file_name: &str, headers: &str) {
    let file_path = get_benchmark_path().join(file_name);
    if let Ok(file) = OpenOptions::new().read(true).open(&file_path) {
        let reader = BufReader::new(file);
        if reader.lines().next().is_none() {
            let mut file = OpenOptions::new().create(true).append(true).open(file_path)
                .expect("Failed to open CSV file");
            writeln!(file, "{}", headers).expect("Failed to write headers");
        }
    } else {
        let mut file = OpenOptions::new().create(true).append(true).open(file_path)
            .expect("Failed to open CSV file");
        writeln!(file, "{}", headers).expect("Failed to write headers");
    }
}

fn append_to_csv(file_name: &str, content: &str) {
    let file_path = get_benchmark_path().join(file_name);
    let mut file = OpenOptions::new().create(true).append(true).open(file_path)
        .expect("Failed to open CSV file");
    writeln!(file, "{}", content).expect("Failed to write to CSV");
}

/// Generic function for benchmarking key exchange
fn run_key_exchange_benchmark<T>(
    cipher_name: &str,
    generate_keypair: impl Fn() -> T,
    extract_keys: impl Fn(&T) -> (&<T as KeyExchange>::PublicKey, &<T as KeyExchange>::PrivateKey),
) 
where
    T: PKITraits + KeyExchange + Clone,
    <T as KeyExchange>::Error: Debug,
{
    let mut sys = System::new_all();
    ensure_headers(
        "pki_key_exchange_benchmark.csv",
        "SetNo,Iteration,Algorithm,EncapsulationTime_ns,DecapsulationTime_ns,Memory_Usage",
    );
    for set_no in 0..ITERATIONS {
        #[allow(unused_variables)]
        let keypair = generate_keypair();
        let peer_keypair = generate_keypair();

        let (peer_public_key, peer_private_key) = extract_keys(&peer_keypair);

        for iteration in 1..=10 {
            sys.refresh_memory();
            let memory_before = sys.total_memory() - sys.free_memory();

            let start_time = Instant::now();
            #[allow(unused_variables)]
            let (shared_secret, ciphertext) =
                <T as KeyExchange>::encapsulate(peer_public_key, None).unwrap();
            let encaps_time = start_time.elapsed().as_nanos();

            let start_time = Instant::now();
            let _ = <T as KeyExchange>::decapsulate(peer_private_key, &ciphertext, None).unwrap();
            let decaps_time = start_time.elapsed().as_nanos();

            sys.refresh_memory();
            let memory_after = sys.total_memory() - sys.free_memory();
            let memory_used = memory_after.saturating_sub(memory_before);

            append_to_csv(
                "pki_key_exchange_benchmark.csv",
                &format!(
                    "{},{},{},{},{},{}",
                    set_no, iteration, cipher_name, encaps_time, decaps_time, memory_used
                ),
            );
        }
    }

    println!(
        "Completed {} key exchange benchmark. Waiting 10 seconds before next algorithm...",
        cipher_name
    );
    sleep(Duration::from_secs(10));
}

/// RSA Key Exchange Benchmark
#[cfg(feature = "pki_rsa")]
fn rsa_key_exchange_benchmark(_c: &mut Criterion) {
    run_key_exchange_benchmark(
        "RSA-OAEP",
        || RSAkeyPair::generate_key_pair().unwrap(),
        |keypair| (&keypair.public_key, &keypair.private_key),
    );
}
#[cfg(not(feature = "pki_rsa"))]
fn rsa_key_exchange_benchmark(_c: &mut Criterion) {
    // no-op if RSA is not enabled
}

/// ECDSA Key Exchange Benchmark (NO-OP stub)
#[cfg(feature = "ecdsa")]
fn ecdsa_key_exchange_benchmark(_c: &mut Criterion) {
    println!("ECDSA feature is enabled, but actual ECDH is not implemented. Doing a no-op benchmark.");
}
#[cfg(not(feature = "ecdsa"))]
fn ecdsa_key_exchange_benchmark(_c: &mut Criterion) {
    // no-op if ecdsa is not enabled
}

/// Ed25519 Key Exchange Benchmark (NO-OP stub)
#[cfg(feature = "ed25519")]
fn ed25519_key_exchange_benchmark(_c: &mut Criterion) {
    println!("Ed25519 feature is enabled, but X25519/ECDH not implemented. Doing a no-op benchmark.");
}
#[cfg(not(feature = "ed25519"))]
fn ed25519_key_exchange_benchmark(_c: &mut Criterion) {
    // no-op if ed25519 is not enabled
}

/// Kyber Key Exchange Benchmark
#[cfg(feature = "kyber")]
fn kyber_key_exchange_benchmark(_c: &mut Criterion) {
    run_key_exchange_benchmark(
        "Kyber",
        || KyberKeyPair::generate_key_pair().unwrap(),
        |keypair| (&keypair.public_key, &keypair.private_key),
    );
}
#[cfg(not(feature = "kyber"))]
fn kyber_key_exchange_benchmark(_c: &mut Criterion) {
    // no-op if kyber is not enabled
}

/// SECP256K1 Key Exchange Benchmark (NO-OP stub)
#[cfg(feature = "secp256k1")]
fn secp256k1_key_exchange_benchmark(_c: &mut Criterion) {
    println!("Secp256k1 feature is enabled, but real ECDH not implemented. Doing a no-op benchmark.");
}
#[cfg(not(feature = "secp256k1"))]
fn secp256k1_key_exchange_benchmark(_c: &mut Criterion) {
    // no-op if secp256k1 is not enabled
}


criterion_group! {
    name = crypto_benchmarks;
    config = Criterion::default().sample_size(10).warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets =
        rsa_key_exchange_benchmark,
        ecdsa_key_exchange_benchmark,
        ed25519_key_exchange_benchmark,
        kyber_key_exchange_benchmark,
        secp256k1_key_exchange_benchmark
}

criterion_main!(crypto_benchmarks);
