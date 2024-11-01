# ZkEmail.rs

This repository contains the core ZkEmail Rust library along with implementations for various ZK Virtual Machines (ZKVMs).

## Overview

ZkEmail is a library for email-based zero-knowledge proofs, allowing verification of email contents while preserving privacy. This monorepo contains both the core library and various ZKVM implementations.

## Repository Structure

```
zkemail/
├── crates/
│   ├── core/          # Core ZkEmail library
│   ├── sp1/           # SP1 ZKVM implementation
│   └── common/        # Shared utilities and types
```

## Implementations

-   **Core Library**: The foundation of ZkEmail, providing email parsing, cryptographic primitives, and proof generation interfaces
-   **SP1**: Implementation using [SP1](https://github.com/succinctlabs/sp1), a RISC-V based zkVM

## Getting Started

### Prerequisites

-   Rust (latest stable)
-   Cargo
-   Additional requirements vary by ZKVM implementation

### Installation

```bash
# Clone the repository
git clone https://github.com/zkemail/zkemail.rs
cd zkemail.rs

# Build all crates
cargo build
```

### Running Tests

```bash
cargo test --workspace
```

## Usage

Each ZKVM implementation has its own specific usage pattern. See the README in each crate's directory for detailed instructions.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
