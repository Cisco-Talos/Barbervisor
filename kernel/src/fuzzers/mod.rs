use crate::coverage::CoverageType;
use crate::fuzzvm::FuzzVm;
use crate::{GuestPhysical, GuestVirtual};
use alloc::boxed::Box;
use alloc::vec::Vec;

/* Available fuzzers */
// pub mod leadtools_ani;
pub mod example;

pub enum Breakpoint {
    Virtual(GuestVirtual),
    Physical(GuestPhysical),
}

/// Closure called to fuzz the snapshot
pub type FuzzFunc = Box<dyn Fn(&mut FuzzVm)>;

/// Closure called to return the input file of the current fuzz run
pub type FuzzFileFunc = Box<dyn Fn(&mut FuzzVm) -> Vec<u8>>;

/// Closure called to insert patches into the snapshot
pub type FuzzPatchFunc = Box<dyn Fn(&mut FuzzVm)>;

/// Closure called to insert hooks into the snapshot
pub type FuzzHookFunc = Box<dyn Fn(&mut FuzzVm)>;

/// Generic Fuzzer implementation.
///
/// The FuzzVm will take a Fuzzer as input and use it as follows:
///
/// In order to tell when a VM has finished execution, a set of `exit_breakpoints` can
/// be set. If these breakpoints are hit, they immediately trigger a VM reset.
///
/// On each VM reset, `fuzz_fn` will be called which should fuzz the current memory of
/// the VM, specific to the fuzz case. After the VM has been "fuzzed", `input_file_fn`
/// which should return the current fuzzed input. This will be sent over TFTP on the
/// event of a crash.
pub trait Fuzzer {
    /// Safety check to make sure the fuzzer matches the given snapshot
    fn start_rip(&self) -> u64;

    /// Timeout based on time (in microseconds)
    fn duration_timeout(&self) -> u64 {
        0
    }

    /// Timeout based on instructions executed
    fn instruction_timeout(&self) -> u64 {
        0
    }

    /// Returns the type of coverage to gather for this fuzzer
    fn coverage_type(&self) -> CoverageType {
        CoverageType::All
    }

    /// Function which will fuzz the current VM
    fn fuzz_fn(&self) -> Option<FuzzFunc> {
        None
    }

    /// Function which returns the current input fuzz case
    fn input_file_fn(&self) -> Option<FuzzFileFunc> {
        None
    }

    /// Breakpoints that are set to tell the VM that the fuzz case is finished.
    /// These breakpoints can only be hit once.
    ///
    /// By default, this will return an empty Vec to signify no exit breakpoints.
    fn exit_breakpoints(&self) -> Vec<Breakpoint> {
        Vec::new()
    }

    /// List of patch function called one time to hard patch bytes in memory in the
    /// local page cache
    ///
    /// (GuestVirtual, bytes to write)
    fn patches(&self) -> Vec<(GuestVirtual, Vec<u8>)> {
        Vec::new()
    }

    /// List of addresses to hook along with callbacks for when that hook is hit.
    /// DOES NOT CURRENTLY HANDLE REPLACING THE BREAKPOINT BYTE.
    fn hooks(&self) -> Vec<(Breakpoint, FuzzHookFunc)> {
        Vec::new()
    }

    /// Function called before the fuzzing function is called
    fn pre_fuzz_fn(&self) -> Option<FuzzFunc> {
        None
    }

    /// Function called after the fuzzing function is called
    fn post_fuzz_fn(&self) -> Option<FuzzFunc> {
        None
    }

    /// Function called during the stats time slot
    fn stats_fn(&self) -> Option<FuzzFunc> {
        None
    }

    /// Function called during single stepping
    fn single_step_fn(&self) -> Option<FuzzFunc> {
        None
    }
}
