# zkemail Profiling Tools

This module provides comprehensive performance profiling tools for analyzing CPU usage, memory allocation patterns, and performance bottlenecks in zkemail operations.

## Overview

The profiling suite consists of:

- **CPU Profiling**: Time measurement utilities with automatic reporting
- **Memory Profiling**: Heap allocation tracking and analysis  
- **Flamegraph Integration**: Visual CPU usage analysis
- **Benchmark Suite**: Continuous performance monitoring

## Components

### Profiling Binaries

#### `email_profiler`
Analyzes performance characteristics of core email processing operations:
- Email parsing performance
- Body extraction efficiency
- DKIM signature verification
- Cryptographic hashing operations

```bash
cargo run --release --bin email_profiler
```

#### `regex_profiler`
Profiles regex pattern matching and compilation:
- Regex compilation performance
- Pattern matching efficiency
- DFA processing benchmarks
- Complex pattern analysis

```bash
cargo run --release --bin regex_profiler
```

#### `generate_regex_data`
Utility for creating compiled DFA test data:
- Generates forward and backward DFA files
- Creates test data for amount and transaction ID patterns

```bash
cargo run --release --bin generate_regex_data
```

### Benchmark Suite

#### Email Benchmarks
Comprehensive email processing performance tests:
- Email parsing (small vs large emails)
- Body extraction benchmarks
- DKIM verification performance
- Hash function benchmarks

```bash
cargo bench --bench email_benchmarks --package zkemail-profiling
```

#### Regex Benchmarks
Pattern matching performance analysis:
- Regex compilation and matching
- DFA creation and processing
- Variable complexity pattern testing

```bash
cargo bench --bench regex_benchmarks --package zkemail-profiling
```

## Usage

### Quick Start

1. **Build the profiling tools:**
   ```bash
   cargo build --release --package zkemail-profiling
   ```

2. **Run comprehensive profiling:**
   ```bash
   # On Linux/macOS
   ./run_profiling.sh
   
   # On Windows
   profile.bat
   ```

3. **Run individual profilers:**
   ```bash
   cargo run --release --bin email_profiler
   cargo run --release --bin regex_profiler
   ```

### Advanced Profiling

#### Flamegraph Generation
For visual CPU usage analysis:

```bash
# Install flamegraph tool
cargo install flamegraph

# Generate flamegraph for email operations
cargo flamegraph --profile=release --bin email_profiler

# Generate flamegraph for benchmarks
cargo flamegraph --profile=release --bench email_benchmarks --package zkemail-profiling -- --bench
```

#### Memory Profiling

**Linux (Valgrind):**
```bash
# Heap profiling with massif
valgrind --tool=massif --massif-out-file=email_massif.out ./target/release/email_profiler

# Generate readable report
ms_print email_massif.out > email_memory_report.txt
```

**Cross-platform (dhat):**
Add to the binary's main function:
```rust
#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

fn main() {
    let _dhat = dhat::Dhat::start_heap_profiling();
    // ... application code
    // Profiling data will be written to dhat-heap.json on exit
}
```

## Library API

The profiling library provides utilities for custom performance analysis:

```rust
use zkemail_profiling::{profile_cpu_usage, setup_memory_profiler};

// Initialize profiling environment
setup_memory_profiler();

// Profile a function's execution time
let result = profile_cpu_usage("data_processing", || {
    // expensive computation
    process_data()
});
```

### Available Functions

- `profile_cpu_usage(name, func)` - Profile function execution time
- `profile_memory_usage(name, func)` - Profile memory usage patterns
- `benchmark_function(name, iterations, func)` - Run performance benchmarks
- `setup_memory_profiler()` - Initialize memory profiling environment

## Output

Profiling results are organized in the `profiling_results/` directory:

```
profiling_results/
├── email_profiler_output.txt          # Email profiler console output
├── regex_profiler_output.txt          # Regex profiler console output
├── email_flamegraph.svg               # CPU profiling visualization
├── regex_flamegraph.svg               # Regex CPU profiling
├── email_bench_flamegraph.svg         # Email benchmark flamegraph
├── regex_bench_flamegraph.svg         # Regex benchmark flamegraph
└── target/criterion/                  # Detailed benchmark reports
```

## Configuration

The workspace is configured for optimal profiling:

```toml
[profile.release]
opt-level = 3       # Maximum optimizations
debug = true        # Include debug symbols for profiling
lto = true          # Enable Link Time Optimization
codegen-units = 1   # Further optimize at compile time
panic = "abort"     # Remove panic unwind code
```

## Requirements

- Rust toolchain (stable)
- `cargo-flamegraph` for visual profiling
- Linux: `perf` tools for advanced flamegraphs
- Linux: `valgrind` for memory profiling

## Platform Support

- **Windows**: Basic profiling with flamegraph support
- **Linux**: Full profiling suite with Valgrind integration
- **macOS**: Flamegraph profiling with DTrace support

## Integration

This profiling suite integrates with:
- Criterion benchmarking framework
- Flamegraph visualization tools
- Valgrind memory analysis (Linux)
- dhat heap profiling (cross-platform)

For detailed analysis workflows, see the main project documentation.
