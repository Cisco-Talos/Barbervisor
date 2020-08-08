//! Leadtools with Gflags snapshot example
//!
//! Example:
//!
//! The snapshot starts at address 0x7ff7ce331a0e
//! Image loaded at address 0x221c993af80 and had a length of 32886
//! The module containing the parser in question was loaded at 0x7ffab6e70000
//! The two breakpoints, if hit, that signify end of fuzz case are in `exit_breakpoints`
use crate::fuzzers::{Breakpoint, FuzzFunc, Fuzzer, FuzzHookFunc};
use crate::fuzzvm::FuzzVm;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::CORPUS;
use crate::GuestVirtual;
use crate::coverage::CoverageType;

pub struct LeadtoolsFuzzer;

const IMAGE_LEN: u64 = 32886;
const IMAGE_ADDR: u64 = 0x221_c993_af80;
const LFANIX: u64 = 0x7ffa_b6e7_0000;
const MEMORY_2017: u64 = 0x7ff7_ce33_0000;

impl Fuzzer for LeadtoolsFuzzer {
    /// Sanity check to make sure the snapshot matches the fuzzer
    fn start_rip(&self) -> u64 {
        if cpu::is_bsp() {
            CORPUS.lock().init("corpus.corpgen");
            // COVERAGE.lock().init("coverage.txt");
        }

        0x7ff7_ce33_1a0e
    }

    /// Timeout after 5 sec 
    fn duration_timeout(&self) -> u64 { 5_000_000 }

    /// Timeout after 20M instructions
    fn instruction_timeout(&self) -> u64 { 20_000_000 }

    fn coverage_type(&self) -> CoverageType {
        // CoverageType::All
        // CoverageType::User
        // CoverageType::Kernel
        CoverageType::Ranges(vec![
            LFANIX..LFANIX+0x1c000
        ])
    }

    /// Fuzz the memory after reset
    fn fuzz_fn(&self) -> Option<FuzzFunc> {
        Some(Box::new(|vm: &mut FuzzVm| {
            // Write one input file from the CORPUS
            if CORPUS.lock().len() > 0 {
                loop {
                    let new_input = CORPUS.lock().mutated_input();
                    if new_input.len() < IMAGE_LEN as usize {
                        vm.write_bytes(GuestVirtual(IMAGE_ADDR), &[0; IMAGE_LEN as usize]);
                        vm.write_bytes(GuestVirtual(IMAGE_ADDR), &new_input);
                        vm.input_file = Some(new_input);
                        break;
                    }
                }
            } else {
                panic!("No corpus found!");
            }
        }))
    }

    /// Set of breakpoints to signify the end of a fuzz case
    fn exit_breakpoints(&self) -> Vec<Breakpoint> {
        vec![
            Breakpoint::Virtual(GuestVirtual(MEMORY_2017+0x1a4d)), // dead0000
            Breakpoint::Virtual(GuestVirtual(MEMORY_2017+0x1ad9)), // dead0001
        ]
    }
}
