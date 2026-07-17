# Issuer-hiding, BBS-based anonymous credentials in Rust

This repository contains a Rust implementation of the issuer-hiding, BBS-based anonymous credentials schemes from https://eprint.iacr.org/2026/870

## Project Structure

- `Cargo.toml`: Standard Cargo manifest with dependencies.
- `src/lib.rs`: The core implementation of the four schemes from the paper.
- `src/msm.rs`: Implementation of helper algorithms for multiexponentiation.
- `src/one_of_l_commitments.rs`: Implementation of a 1-of-l commitment scheme based on Ristretto-255.
- `src/blst-wrappers.rs`: Used for efficient implementation of BLS12-381.
- `tests/integration_test.rs`: End-to-end tests of correctness demonstrating usage.

## Prerequisites

To compile and run this library, you need:

1. Rust Toolchain: Install via rustup.rs:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

3. C Build Tools (required by blst to compile assembly and C sources):
Linux: Install build-essential (gcc/clang, make):
```bash
sudo apt-get install build-essential
```

Windows: Install Visual Studio Build Tools with the "Desktop development with C++" workload, or use MinGW.

## Usage & Running Tests

To verify that everything compiles and passes the integration tests, run:

```bash
cargo test
```
