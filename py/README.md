# Python Bindings for Nautilus

This project provides Python bindings for the Nautilus ecosystem using Rust's pyo3 library. The bindings expose the core functionality of multiple Nautilus crates to Python, enabling integration with Python applications.

## Features

- Rust-Python Interoperability: Exposes key functionality from multiple Rust crates (e.g., `nautilus_pki`, `nautilus_mdns`, etc.) to Python.
- Post-Quantum Cryptography (PQC): Bindings for PQC algorithms such as Dilithium, Falcon, and Kyber.
- Decentralized Identity: Support for Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs).
- Networking: Provides mDNS-based peer discovery and other networking utilities.
- Easy Integration: Simple interface to integrate Nautilus functionality into Python projects.
