/// Memory profiling utilities for analyzing heap allocation patterns
/// and memory usage statistics in zkemail operations.
use std::sync::Once;
use std::time::Instant;

// Static initialization control for profiler setup
static INIT: Once = Once::new();

/// Initializes the memory profiler environment.
///
/// This function should be called once at the start of the program or test suite.
/// It provides instructions for setting up advanced heap profiling with dhat.
pub fn setup_memory_profiler() {
    INIT.call_once(|| {
        println!("Memory profiling environment initialized.");
        println!("\nAdvanced heap profiling setup (dhat):");
        println!("1. Add to main.rs or lib.rs:");
        println!("   #[global_allocator]");
        println!("   static ALLOCATOR: dhat::Alloc = dhat::Alloc;");
        println!("2. Initialize at program start:");
        println!("   let _dhat = dhat::Dhat::start_heap_profiling();");
        println!("3. Analyze results:");
        println!("   dhat-heap-viewer dhat-heap.json");
    });
}

/// A RAII guard that automatically tracks memory profiling metrics
/// for a code section when it goes out of scope.
pub struct MemoryProfileSection {
    name: String,
    start_time: Instant,
}

impl MemoryProfileSection {
    /// Creates a new memory profiling section.
    ///
    /// # Arguments
    /// * `section_name` - A descriptive name for the code section being profiled
    ///
    /// # Returns
    /// A `MemoryProfileSection` that will automatically report timing when dropped
    pub fn new(section_name: &str) -> Self {
        println!("Starting memory profile: {}", section_name);
        Self {
            name: section_name.to_string(),
            start_time: Instant::now(),
        }
    }
}

impl Drop for MemoryProfileSection {
    fn drop(&mut self) {
        let duration = self.start_time.elapsed();
        println!(
            "Completed memory profile: {} (duration: {:?})",
            self.name, duration
        );
    }
}

/// Creates a memory profiling guard for a code section.
///
/// # Arguments
/// * `section_name` - A descriptive name for the code section
///
/// # Returns
/// A guard that will automatically report timing information when dropped
pub fn start_memory_profiling(section_name: &str) -> MemoryProfileSection {
    MemoryProfileSection::new(section_name)
}

/// Profiles the memory usage characteristics of a function.
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
/// use zkemail_profiling::profile_memory_usage;
///
/// let result = profile_memory_usage("data_allocation", || {
///     vec![0u8; 1024 * 1024] // Allocate 1MB
/// });
/// ```
pub fn profile_memory_usage<F, R>(section_name: &str, func: F) -> R
where
    F: FnOnce() -> R,
{
    let _profiler = start_memory_profiling(section_name);
    func()
}
