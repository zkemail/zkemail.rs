/// Performance profiling utilities for zkemail analysis.
///
/// This library provides comprehensive profiling tools for analyzing CPU usage,
/// memory allocation patterns, and performance bottlenecks in zkemail operations.
///
/// # Features
///
/// - **CPU Profiling**: Time measurement utilities with automatic reporting
/// - **Memory Profiling**: Heap allocation tracking and analysis
/// - **Flamegraph Integration**: Helper utilities for flame graph generation
/// - **Benchmark Support**: Consistent performance measurement tools
///
/// # Examples
///
/// ```rust
/// use zkemail_profiling::{profile_cpu_usage, setup_memory_profiler};
///
/// // Initialize profiling environment
/// setup_memory_profiler();
///
/// // Profile a function's execution time
/// let result = profile_cpu_usage("data_processing", || {
///     // expensive computation
///     42
/// });
/// ```
pub mod cpu_profiler;
pub mod memory_profiler;

// Re-export commonly used profiling functions for convenience
pub use cpu_profiler::{benchmark_function, profile_cpu_usage, start_cpu_profiling};
pub use memory_profiler::{profile_memory_usage, setup_memory_profiler, start_memory_profiling};
