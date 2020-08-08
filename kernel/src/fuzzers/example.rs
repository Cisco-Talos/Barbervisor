//! Example fuzzer

use crate::fuzzers::{Breakpoint, FuzzFunc, Fuzzer};
use crate::fuzzvm::FuzzVm;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::coverage::CoverageType;

pub struct ExampleFuzzer;

const IMAGE_LEN: u64 = 32886;
const IMAGE_ADDR: u64 = 0x221_c993_af80;

impl Fuzzer for ExampleFuzzer {
    /// Sanity check to make sure the snapshot matches the fuzzer
    fn start_rip(&self) -> u64 {
        if cpu::is_bsp() {
            // CORPUS.lock().init("corpus.corpgen");
            // COVERAGE.lock().init("coverage.txt");
        }

        0x7ff6_1ca4_11e4
    }

    /// Timeout after 1 sec 
    fn duration_timeout(&self) -> u64 { 1_000_000 }

    /// Timeout after 20M instructions
    fn instruction_timeout(&self) -> u64 { 20_000_000 }

    fn coverage_type(&self) -> CoverageType {
        CoverageType::None
        // CoverageType::All
        // CoverageType::User
        // CoverageType::Kernel
    }

    /// Fuzz the memory after reset
    fn fuzz_fn(&self) -> Option<FuzzFunc> {
        Some(Box::new(|_vm: &mut FuzzVm| {
        }))
    }

    /// Set of breakpoints to signify the end of a fuzz case
    fn exit_breakpoints(&self) -> Vec<Breakpoint> {
        vec![
            // Breakpoint::Virtual(GuestVirtual(0x1a4d)),
            // Breakpoint::Virtual(GuestVirtual(0x1ad9)),
        ]
    }
}
