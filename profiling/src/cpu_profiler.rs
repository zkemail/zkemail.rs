/// CPU profiling utilities for analyzing performance bottlenecks
/// in zkemail processing operations.
use std::time::{Duration, Instant};

/// A RAII guard that automatically tracks and reports execution time
/// for a code section when it goes out of scope.
pub struct CpuProfileSection {
    name: String,
    start_time: Instant,
}

impl CpuProfileSection {
    /// Creates a new CPU profiling section.
    ///
    /// # Arguments
    /// * `section_name` - A descriptive name for the code section being profiled
    ///
    /// # Returns
    /// A `CpuProfileSection` that will automatically report timing when dropped
    pub fn new(section_name: &str) -> Self {
        println!("Starting CPU profile: {}", section_name);
        Self {
            name: section_name.to_string(),
            start_time: Instant::now(),
        }
    }
}

impl Drop for CpuProfileSection {
    fn drop(&mut self) {
        let duration = self.start_time.elapsed();
        println!(
            "Completed CPU profile: {} (duration: {:?})",
            self.name, duration
        );
    }
}

/// Creates a CPU profiling guard for a code section.
///
/// # Arguments
/// * `section_name` - A descriptive name for the code section
///
/// # Returns
/// A guard that will automatically report timing information when dropped
pub fn start_cpu_profiling(section_name: &str) -> CpuProfileSection {
    CpuProfileSection::new(section_name)
}

/// Profiles the execution time of a function.
///
/// # Arguments
/// * `section_name` - A descriptive name for the profiling section
/// * `func` - The function to profile
///
/// # Returns
/// The return value of the profiled function
///
/// # Examples
/// ```
/// use zkemail_profiling::profile_cpu_usage;
///
/// let result = profile_cpu_usage("data_processing", || {
///     // expensive computation
///     42
/// });
/// ```
pub fn profile_cpu_usage<F, R>(section_name: &str, func: F) -> R
where
    F: FnOnce() -> R,
{
    let _profiler = start_cpu_profiling(section_name);
    func()
}

/// Benchmarks a function by running it multiple times and computing average execution time.
///
/// # Arguments
/// * `name` - A descriptive name for the benchmark
/// * `iterations` - Number of times to run the function
/// * `func` - The function to benchmark
///
/// # Returns
/// The average execution time per iteration
///
/// # Note
/// This function performs a 5-iteration warmup before timing to ensure accurate measurements.
pub fn benchmark_function<F>(name: &str, iterations: u32, func: F) -> Duration
where
    F: Fn(),
{
    println!("Benchmarking '{}' ({} iterations)", name, iterations);

    // Perform warmup iterations to stabilize performance
    for _ in 0..5 {
        func();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        func();
    }
    let total_duration = start.elapsed();
    let avg_duration = total_duration / iterations;

    println!(
        "Benchmark '{}': average: {:?}, total: {:?}",
        name, avg_duration, total_duration
    );
    avg_duration
}

/// Provides comprehensive instructions for setting up and using flamegraph profiling.
///
/// # Returns
/// A formatted string containing installation and usage instructions
pub fn setup_flamegraph_instructions() -> String {
    let instructions = r#"Flamegraph Profiling Setup

Installation:
1. Install cargo-flamegraph:
   cargo install flamegraph

2. Linux requirements:
   sudo apt-get install linux-tools-common linux-tools-generic

3. Windows users should use WSL or install Windows Performance Toolkit

Usage:
• Profile benchmarks:
  cargo flamegraph --profile=release --bench email_benchmarks -- --bench

• Profile specific tests:
  cargo flamegraph --profile=release -- --test test_name

• Profile binaries:
  cargo flamegraph --profile=release --bin email_profiler

Output:
The flamegraph will be saved as 'flamegraph.svg' in the current directory.
Open with a web browser to analyze CPU usage patterns."#;

    instructions.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_profiling_functionality() {
        let _section = start_cpu_profiling("test_section");
        // Simulate computational work
        std::thread::sleep(Duration::from_millis(10));
    }

    #[test]
    fn test_benchmark_accuracy() {
        let duration = benchmark_function("sleep_benchmark", 5, || {
            std::thread::sleep(Duration::from_millis(2));
        });
        assert!(duration.as_millis() >= 2);
    }
}
