#![no_std]
#![no_main]
#![feature(const_fn)]
#![feature(lang_items)]
#![feature(core_intrinsics)]
#![feature(allocator_api)]
#![feature(llvm_asm)]
#![allow(dead_code)]
#![allow(safe_packed_borrows)]
#![feature(global_asm)]
#![feature(panic_info_message)]
#![feature(arbitrary_enum_discriminant)]
#![recursion_limit="256"]

// Phil OS features needed
#![feature(custom_test_frameworks)]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]
#![feature(exclusive_range_pattern)]
#![feature(naked_functions)]

#![allow(deprecated)]
#![allow(deprecated_in_future)]

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate noodle;
use noodle::{Serialize, Deserialize};

extern crate cpu;
extern crate mmu;
extern crate rangeset;
extern crate serial;
extern crate volatile;

#[macro_use]
extern crate bytesafe_derive;

#[macro_use]
extern crate bitflags;

extern crate log;

extern crate packets;

#[macro_use]
extern crate lazy_static;

// no_std hashmap impl
extern crate hashbrown;
use hashbrown::{HashMap, HashSet};

/* Useful macros of int <-> enum conversions */
extern crate num;
#[macro_use]
extern crate num_derive;

use core::sync::atomic::{AtomicUsize, Ordering, AtomicBool, AtomicU64};
use alloc::vec::Vec;
use alloc::string::ToString;

/* Needed to fix the following error */
/*
= note: lld-link: error: undefined symbol: _fltused
        >>> referenced by libcompiler_builtins-aaba56e480d3b6ad.rlib(floatdisf.o)
*/
#[no_mangle]
pub fn __fltused() {
    panic!("Fail");
}

#[no_mangle]
pub fn _fltused() {
    panic!("Fail");
}

#[global_allocator]
static GLOBAL_ALLOCATOR: mm::GlobalAllocator = mm::GlobalAllocator;

#[derive(PartialEq, Eq)]
enum Cores {
    Single,
    Multi,
}

#[derive(PartialEq, Eq)]
enum LogLevel {
    Info,
    Debug,
}

/* Few global config options */
const CORES: Cores = Cores::Single;
const LOG: LogLevel = LogLevel::Info;
const MAX_CORES: usize = 2;
static KEYBOARD_BP: AtomicBool = AtomicBool::new(false);

/// Bring in VGA print capabilities
#[macro_use]
pub mod vga_buffer;

/// ACPI code
pub mod acpi;

/// Panic handler
pub mod panic;

/// Core requirements needed for Rust, such as libc memset() and friends
pub mod core_reqs;

/// Bring in the memory manager
pub mod mm;

/// Volatile wrappers
mod idt;

/// Enable interrupts
#[macro_use]
pub mod interrupts;

/// Gdt helpers
pub mod gdt;

/// Intel Vt-x helpers
pub mod vmx;
use vmx::{vmread, vmwrite};

/// Intel Vt-x bitflags
pub mod vmxflags;
use vmxflags::{Cr4, Cr4Flags};

/// Statistics kept about the fuzz cases
#[macro_use]
mod stats;

/// Intel Vt-x MSR constants
mod msr;
use msr::*;

/// PCI implementation
mod pci;

/// Network driver implementations
mod net;
use net::i219;

/// Utilities to be used in fuzzing
mod tools;

/// Modules used for decoding values from VmExits
mod vmexit;
use vmexit::*;

mod vmregs;

/// Time utilities for sleep
mod time;

use fuzzvm::FuzzVm;
use vmregs::{Vbcpu, XSAVE_AREA_SIZE};

/// Slightly modified mmu for Extended Page Tables
mod ept;

/// Struct implementation for setting up our fuzzed VM
mod fuzzvm;

/// Pseudo Random Number generation
mod rng;
use rng::Rng;

/// Load the existing fuzzers
mod fuzzers;
use fuzzers::*;

/// Module for handling tracing
mod trace;

/// Module for handling coverage
mod coverage;
use coverage::COVERAGE;

/// Module for handling corpus input/mutation
mod corpus;

mod mutations;

/// Module for handling the MSR Bitmap
mod msr_bitmap;

mod ni;

mod file;
use file::Files;

use alloc::boxed::Box;

/// Writer implementation used by the `print!` macro
pub struct Writer;

/// Wrapper struct for Guest Virtual addresses
#[derive(PartialEq, Eq, Hash, Copy, Clone, Default, Debug)]
pub struct GuestVirtual(u64);

/// Wrapper struct for Guest Physical addresses
#[derive(PartialEq, Eq, Hash, Copy, Clone, Default, Debug)]
pub struct GuestPhysical(u64);

/// Wrapper struct for Kernel Physical addresses
#[derive(PartialEq, Eq, Hash, Copy, Clone, Default, Debug)]
pub struct KernelPhysical(u64);

#[lang = "oom"]
#[no_mangle]
pub extern "C" fn rust_oom(_layout: alloc::alloc::Layout) -> ! {
    panic!("Out of memory");
}

#[macro_export]
macro_rules! dbg {
    ( $($arg:tt)* ) => ({
        use crate::{LOG, LogLevel};
        if LOG == LogLevel::Debug {
            $crate::vga_print!($($arg)*);
        }
    })
}

fn kernel_init() {
    interrupts::init_idt();
    unsafe { interrupts::PICS.lock().initialize(); }
    x86_64::instructions::interrupts::enable();

    vmx::init();

    unsafe {
        Cr4::insert(Cr4Flags::OS_SUPPORT_FOR_FXSAVE_FXRSTOR);
        Cr4::insert(Cr4Flags::XSAVE_PROCESSOR_EXTENDED_STATES_ENABLE_BIT);
    }
    unsafe {
        // Enable AVX, SSE, X87
        core::arch::x86_64::_xsetbv(0, 7);
    }
}


pub static CORE_ID: AtomicUsize = AtomicUsize::new(0);
pub static REBOOT_ADDR: AtomicU64 = AtomicU64::new(0);
pub static KBUF_ADDR: AtomicU64 = AtomicU64::new(0);

pub fn hard_reset() {
    /* outb(0x64, 0xfe) to 8042 reset */
    unsafe {
        llvm_asm!(r"mov al, 0xfe; out 0x64, al" : // Assembly
                                           : // Output
                                           : // Input
                                           : // Clobbered registers
            "volatile", "intel");            // Options
    }
}


/// Main entry point for this codebase
#[no_mangle]
pub extern "C" fn entry(param: u64) -> ! {
    if cpu::is_bsp() {
        // Store off the current rdtsc value
        let start = cpu::rdtsc();
        print!("rdtsc at boot is: {}\n", start);

        // Store this off as the system boot time
        time::BOOT_TIME.store(start as usize, Ordering::SeqCst);
    }

    unsafe {
        let cpuid = core::arch::x86_64::__cpuid(1);
        assert!((cpuid.ecx >> 28) & 1 == 1, "AVX not found in CPUID");
        assert!((cpuid.edx >> 25) & 1 == 1, "SSE not found in CPUID");
        assert!((cpuid.edx >> 26) & 1 == 1, "SSE2 not found in CPUID");
    }

    // Convert the bootloader parameter into a reference
    let param = unsafe { &*(param as *const cpu::BootloaderStruct) };

    // Get a unique core identifier for this processor
    let core_id = CORE_ID.load(Ordering::SeqCst);

    kernel_init();
    
    if cpu::is_bsp() {
        unsafe {
            print!("init pics\n");
            time::calibrate();
            acpi::init(&param.phys_memory).expect("Failed to initialize ACPI");
        }

        // Call get_file to init nic
        let _ = net::get_file("SNAPSHOT_regs");
    }

    // Download snapshot register state
    let snapshot_vbcpu_data = net::get_file("SNAPSHOT_regs");
    
    // Deserialize the Vbcpu
    let mut vbcpu = unsafe { &mut *(snapshot_vbcpu_data.as_ptr() as *mut Vbcpu) };

    assert!(vbcpu.cbext as usize == XSAVE_AREA_SIZE);
    vbcpu.ldtr.limit = 0xffffffff;
    vbcpu.ldtr.access_rights = 0x1c000;

    // Create the FuzzVm itself with the current fuzzer
    let mut fuzzvm = FuzzVm::new(*vbcpu, (core_id + 1) as u32, example::ExampleFuzzer {});

    // Enable single step globally
    let global_single_step = true;

    // Preemption timer
    let preemption_timer = if !global_single_step { 40000 } else { 1000 };

    // Determine whether the VM should be in single step mode or not
    if cpu::is_bsp() {
        if global_single_step {
            fuzzvm.enable_single_step();
        } else {
            fuzzvm.disable_single_step();
        }

        print!("First run single");
        fuzzvm.enable_single_step();
        fuzzvm.set_preemption_timer_per_second(0);
    } else {
        fuzzvm.disable_single_step();
        fuzzvm.set_preemption_timer_per_second(preemption_timer);
    }

    let stats_time = 5_000_000;
    let cov_time = 1_000_000;
    let put_cov_time = 15_000_000;
    let mut time_check: u64 = time::future(stats_time);
    let mut cov_time_check: u64 = time::future(cov_time);
    let mut put_cov_time_check: u64 = time::future(put_cov_time);
    let mut _lock_check: u64 = time::future(stats_time);
    let mut duration_timeout: u64 = time::future(0xffff_ffff);

    // Used to signify the first run through the fuzz run. Used to signal when 
    // to spin up the other cores on the system.
    let mut first_run = true;
    let mut dry_run = true;

    let last_user_rip = 0;
    
    loop {
        if cpu::is_bsp() {
            if time_check < time::rdtsc() && !first_run {
                let timer_start_print_stats = time::rdtsc();
                stats::print_debug();
                stats::print();
                // print!("Length: {}\n", fuzzvm.executed_instrs);
                time_check = time::future(stats_time);
                stats::DEBUG_TIME_PRINT_STATS.fetch_add(time::rdtsc() - timer_start_print_stats,
                    Ordering::Acquire);

                // Call the Fuzzer's stats callback
                fuzzvm.stats_callback();
            }

            if cov_time_check < time::rdtsc() && !first_run {
                // Mark down the current amount of coverage
                let mut cov = COVERAGE.lock();
                cov.mark_graph();
                cov_time_check = time::future(cov_time);

                // Call get_file to keep clearing the descriptors
                let _ = net::get_file("SNAPSHOT_regs");

            }

            // If put coverage timeout elapsed, put the coverage.txt
            if put_cov_time_check < time::rdtsc() && !first_run {
                let mut cov = COVERAGE.lock();
                cov.put("coverage.txt");
                put_cov_time_check = time::future(put_cov_time);
            }

        }

        // Execute the VM
        let vmexit_reason = fuzzvm.run();

        // Gather important information about the VmExit
        let error_code = vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE);
        let exit_qual = vmread(VMCS_EXIT_QUALIFICATION);
        let exit_info = vmread(VMCS_VMEXIT_INTERRUPTION_INFO);

        stats::VMEXIT_TOTAL.fetch_add(1, Ordering::Acquire);
        match vmexit_reason {
            VmExitReason::Exception(vector) => {
                let interruption_info = InterruptionInfo::from(exit_info);
                // print!("Interrupt Vec: {:?}\n", interruption_info.vector());
                match vector {
                    ExceptionVector::PageFault => {
                        // Perf counter increment
                        stats::VMEXIT_PAGE_FAULT.fetch_add(1, Ordering::Acquire);

                        let timer_start_pf = time::rdtsc();

                        // Pass the exception back to the guest
                        fuzzvm.inject_page_fault();

                         stats::DEBUG_TIME_PF.fetch_add(time::rdtsc() - timer_start_pf as u64, 
                            Ordering::Acquire);
                    }
                    ExceptionVector::Debug => {
                        // Perf counter increment
                        stats::VMEXIT_DEBUG.fetch_add(1, Ordering::Acquire);

                        fuzzvm.regs.print();
                        panic!("DEBUG EXCEPTION");
                    }
                    ExceptionVector::Divider => {
                        // Perf counter increment
                        stats::VMEXIT_DIVIDER.fetch_add(1, Ordering::Acquire);

                        fuzzvm.regs.print();
                        panic!("DIV EXCEPTION");
                    }
                    ExceptionVector::Breakpoint => {
                        // Perf counter increment
                        stats::VMEXIT_BREAKPOINT.fetch_add(1, Ordering::Acquire);

                        let timer_start_bp = time::rdtsc();

                        // HalProcessorIdle
                        const HALPROCESSORIDLE_NEEDLE: [u8; 16] = [
                            0xcc, 0x83, 0xec, 0x28, 0xe8, 0xe7, 0x32, 0xfa, 0xff, 0x48, 0x83,
                            0xc4, 0x28, 0xfb, 0xf4, 0xc3,
                        ];

                        // HalRequestSoftwareInterrupt
                        const HALREQUESTSOFTWAREINTERRUPT_NEEDLE: [u8; 40] = [
                            0xcc, 0x83, 0xec, 0x48, 0x33, 0xc0, 0xf, 0x57, 0xc0, 0x80,
                            0xf9, 0x1, 0x48, 0x89, 0x44, 0x24, 0x30, 0xf, 0x11, 0x44,
                            0x24, 0x20, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0xc7, 0x44, 0x24,
                            0x20, 0x5, 0x0, 0x0, 0x0, 0x8d, 0x50, 0x1f, 0x8d, 0x42,
                        ];

                        let halprocessoridle_test = fuzzvm.read_bytes(GuestVirtual(fuzzvm.get_rip()), 
                            HALPROCESSORIDLE_NEEDLE.len() as u64);
                        let halrequestsoftwareinterrupt_test = fuzzvm.read_bytes(GuestVirtual(fuzzvm.get_rip()), 
                            HALREQUESTSOFTWAREINTERRUPT_NEEDLE.len() as u64);

                        if halrequestsoftwareinterrupt_test[00..20] == HALREQUESTSOFTWAREINTERRUPT_NEEDLE[00..20] 
                              && halrequestsoftwareinterrupt_test[20..40] == HALREQUESTSOFTWAREINTERRUPT_NEEDLE[20..40] {
                                // Hit HalRequestSoftwareInterrupt
                                fuzzvm.tag = format!("-HALINT_{:x}", fuzzvm.regs.rcx);
                                stats::HAL_INTERRUPT_COUNT.fetch_add(1, Ordering::Acquire);

                                // Jump to the end of the function
                                fuzzvm.set_rip(fuzzvm.get_rip() + 0x35);
                        } else if halprocessoridle_test == HALPROCESSORIDLE_NEEDLE {
                            // print!("PROCESSOR IDLE!\n");

                            match &fuzzvm.input_file {
                                Some(ref input_file) => {
                                    net::put_file(
                                        &format!(
                                            "halidle_{}_{:x}_{:x}_{:x}.currcalls",
                                            fuzzvm.core_id, fuzzvm.regs.rcx, fuzzvm.regs.rdx, fuzzvm.regs.r8, 
                                        ),
                                        input_file
                                    );
                                }
                                None => { print!("[halidle] No input file given..\n") }
                            }

                            fuzzvm.tag = "-HALIDLE".to_string();

                            stats::HAL_INTERRUPT_COUNT.fetch_add(1, Ordering::Acquire);

                            fuzzvm.should_resume = false;
                        } else if fuzzvm.hooks.contains_key(&GuestVirtual(fuzzvm.get_rip())) {
                            // Get the callback for this RIP, safe to unwrap due to the previous 
                            // check

                            // We need to take ownership of the callback in order to pass a &mut
                            // fuzzvm to the call back itself. To achieve this, we remove the
                            // entry from the hashmap, which is safe due to the `contains_key`
                            // check above. We then re-insert the callback back into the hashmap.
                            let start_rip = fuzzvm.get_rip();
                            let curr_rip = GuestVirtual(start_rip);
                            let callback = fuzzvm.hooks.remove_entry(&curr_rip).unwrap().1;
                            callback(&mut fuzzvm);
                            fuzzvm.hooks.insert(curr_rip, Box::new(callback));
                        } else if fuzzvm.exit_breakpoints.contains(&GuestVirtual(fuzzvm.get_rip())) {
                            // Otherwise, check if the breakpoint was set by us, in our
                            // exit breakpoints. If not, hard panic.

                            // This is one of our reset breakpoint.
                            // Increase the fuzz count and reset the VM.

                            // Attempt to launch the next processor in the list if we are in 
                            // multicore mode
                            if CORES == Cores::Multi 
                                && CORE_ID.load(Ordering::SeqCst) < (MAX_CORES-1) 
                                && first_run {
                                let core_id = CORE_ID.fetch_add(1, Ordering::SeqCst);
                                unsafe {
                                    if !acpi::launch_ap(core_id + 1) {
                                        print!(
                                            "Failed to launch ap with core id: {}\n",
                                            core_id + 1
                                        );
                                    }
                                }

                                print!("[{}] Starting next core..\n", fuzzvm.core_id);

                                // Wait for all cores to catch up
                                while CORE_ID.load(Ordering::SeqCst) != (MAX_CORES-1) { }
                                first_run = false;
                            }

                            if first_run {
                                let sleep = (fuzzvm.core_id-1) * 500 * 1000;
                                // print!("[{}] Sleeping {}\n", fuzzvm.core_id, sleep);
                                time::sleep(sleep as u64);
                                print!("[{}] OFF TO THE RACES!\n", fuzzvm.core_id);
                            }

                            // Either the single core sets first_run to false or the LAST core, in
                            // multicore, to be initialized sets the first_run to false
                            if first_run {
                                if  CORES == Cores::Single 
                                || (CORES == Cores::Multi && fuzzvm.core_id == MAX_CORES as u32) {
                                    stats::reset();
                                    first_run = false;
                                }
                            }

                            // Reset timers because of reset breakpoint
                            duration_timeout = time::future(fuzzvm.duration_timeout);
                            fuzzvm.should_resume = false;
                            if global_single_step {
                                fuzzvm.enable_single_step();
                            } else {
                                fuzzvm.disable_single_step();
                            }
                            fuzzvm.set_preemption_timer_per_second(preemption_timer);

                        } else {
                            // Hit an unknown breakpoint..
                            fuzzvm.regs.print();
                            fuzzvm.trace.push(fuzzvm.get_rip());
                            fuzzvm.should_resume = false;
                            fuzzvm.tag = "-UNKNOWNBP".to_string();
                            fuzzvm.put_trace("unknown_bp");
                            let stack = fuzzvm.read_bytes(GuestVirtual(fuzzvm.regs.rsp), 0x1000);
                            net::put_file("unknown_bp_stack", &stack);
                            let stack = fuzzvm.read_bytes(GuestVirtual(fuzzvm.regs.rbp), 0x1000);
                            net::put_file("unknown_bp_base", &stack);
                            panic!();
                        }

                        stats::DEBUG_TIME_BP.fetch_add(time::rdtsc() - timer_start_bp,
                            Ordering::Acquire);
                    }
                    ExceptionVector::GeneralProtection => {
                        // Pass the exception back to the guest
                        fuzzvm.inject_general_protection_fault();
                        
                        // Perf counter increment
                        stats::VMEXIT_GENERAL_PROTECTION.fetch_add(1, Ordering::Acquire);

                        fuzzvm.put_trace(
                            &format!("GP_{:x}.trace", fuzzvm.get_rip())
                        );
                        fuzzvm.put_verbose_trace(
                            &format!("GP_{:x}.verbosetrace", fuzzvm.get_rip())
                        );
                        match &fuzzvm.input_file {
                            Some(ref input_file) => {
                                net::put_file(
                                    &format!("GP_{:x}.trace", fuzzvm.get_rip()),
                                    input_file
                                );
                            }
                            None => { print!("[#GP] No input file given..\n") }
                        }

                        fuzzvm.regs.print();
                        panic!("#GP EXCEPTION");
                    }
                    ExceptionVector::InvalidOpcode => {
                        // Perf counter increment
                        stats::VMEXIT_INVALID_OPCODE.fetch_add(1, Ordering::Acquire);

                        fuzzvm.regs.print();
                        panic!("INVALID OPCODE EXCEPTION");
                    }
                    ExceptionVector::SIMDFloatingPoint => {
                        // Ship over the input that caused a SIMD crash
                        match &fuzzvm.input_file {
                            Some(ref input_file) => {
                                net::put_file(
                                    &format!("simd_{}_{:x}.input",
                                        fuzzvm.core_id, fuzzvm.get_rip()),
                                    input_file
                                );
                            }
                            None => { print!("[simd] No input file given..\n") }
                        }

                        stats::INSTR_PER_CRASH.fetch_add(fuzzvm.executed_instrs, Ordering::Acquire);
                        stats::CRASH_COUNT.fetch_add(1, Ordering::Acquire);
                        fuzzvm.should_resume = false;

                        fuzzvm.regs.print();
                        panic!("SIMD");
                    }
                    _ => {
                        // Generic handler for exceptions not yet handled
                        print!("NOT HANDLING: {:?}\n", interruption_info.vector());
                        print!("QUAL - {:#x}\n", exit_qual);
                        print!("INFO - {:?}\n", interruption_info);
                        let interruption_info = InterruptionInfo::from(exit_info);
                        if interruption_info.is_error_code_valid() {
                            print!("Error code - {:#x}\n", error_code);
                        }
                        print!("Last user rip: {:#x}\n", last_user_rip);
                        fuzzvm.regs.print();
                        fuzzvm.put_trace("test.trace");
                        fuzzvm.put_verbose_trace("test.verbosetrace");
                        panic!();
                    }
                }

            }
            VmExitReason::EPTViolation => {
                // EPT Violation - Memory needed in the VM isn't mapped in the EPT
                //
                // Perf counter increment
                stats::VMEXIT_EPT.fetch_add(1, Ordering::Acquire);

                // Start the timer for the EPTViolation for stats
                let timer_start_ept = time::rdtsc();

                // Grab physical page causing fault
                let fault_addr_phys =
                    GuestPhysical(vmread(VMCS_GUEST_PHYSICAL_ADDR) & 0xffff_ffff_ffff_f000);

                match fault_addr_phys.0 {
                    0xe0000 => { 
                        panic!("Mapping RSDPTR");
                    }
                    // Map APIC addresses to the Guest
                    0xfed00000 | 0xfee00000 => {
                        // panic!("[{}] MMIO mapping APIC addr {:#x}\n", fuzzvm.core_id, fault_addr_phys.0);
                        // fuzzvm.kernel_identity_map(KernelPhysical(fault_addr_phys.0));
                        panic!("MAPPING APIC");
                    }
                    0xe0000000..0xe0300000 => {
                        panic!("[{}] MMIO blank mapping (display?) {:#x}\n", fuzzvm.core_id, fault_addr_phys.0);
                    }
                    _ => {
                        // Map that physical page to the VM
                        fuzzvm.map_page_phys(fault_addr_phys);
                    }
                }

                // Invalidate previous EPT entries
                fuzzvm.invept_global();

                // Mark time for VM execution
                stats::DEBUG_TIME_EPT.fetch_add(time::rdtsc() - timer_start_ept, Ordering::Acquire);
            }
            VmExitReason::ControlRegisterAccess(register, instr_type, value) => {
                // VmExit from mov to/from control register
                
                // Start timer for Control
                let timer_start_control_regs = time::rdtsc();

                // Currently only handling mov to cr3 exits
                match register {
                    3|8 => {}
                    _ => panic!("Not handling mov to/from cr[024]"),
                };

                match (instr_type, register) {
                    (0,3) => {
                        /* mov to cr3 */
                        // Perf counter increment
                        stats::VMEXIT_MOV_CR3_XXX.fetch_add(1, Ordering::Acquire);

                        let new_value = match (exit_qual >> 8) & 0xf {
                            0 => fuzzvm.regs.rax,
                            1 => fuzzvm.regs.rcx,
                            2 => fuzzvm.regs.rdx,
                            3 => fuzzvm.regs.rbx,
                            4 => fuzzvm.regs.rsp,
                            5 => fuzzvm.regs.rbp,
                            6 => fuzzvm.regs.rsi,
                            7 => fuzzvm.regs.rdi,
                            8 => fuzzvm.regs.r8,
                            9 => fuzzvm.regs.r9,
                            10 => fuzzvm.regs.r10,
                            11 => fuzzvm.regs.r11,
                            12 => fuzzvm.regs.r12,
                            13 => fuzzvm.regs.r13,
                            14 => fuzzvm.regs.r14,
                            15 => fuzzvm.regs.r15,
                            _ => panic!("Unknown register in handling control regs"),
                        };

                        if new_value == 0 {
                            fuzzvm.regs.print();
                            print!("Exit qual: {:#x}\n", exit_qual);
                            panic!("NEW CR3 is zero?!");
                        }

                        // Invalidate TLB on rewrite cr3 
                        fuzzvm.invvpid_keep_global();

                        // Create new maps/ept for the new cr3
                        fuzzvm.new_cr3(new_value & !(1 << 63));
                    }
                    (1,3) => {
                        /* mov from cr3 */
                        // Perf counter increment
                        stats::VMEXIT_MOV_XXX_CR3.fetch_add(1, Ordering::Acquire);

                        match (exit_qual >> 8) & 0xf {
                            0 => fuzzvm.regs.rax = fuzzvm.cr3,
                            1 => fuzzvm.regs.rcx = fuzzvm.cr3,
                            2 => fuzzvm.regs.rdx = fuzzvm.cr3,
                            3 => fuzzvm.regs.rbx = fuzzvm.cr3,
                            4 => fuzzvm.regs.rsp = fuzzvm.cr3,
                            5 => fuzzvm.regs.rbp = fuzzvm.cr3,
                            6 => fuzzvm.regs.rsi = fuzzvm.cr3,
                            7 => fuzzvm.regs.rdi = fuzzvm.cr3,
                            8 => fuzzvm.regs.r8 = fuzzvm.cr3,
                            9 => fuzzvm.regs.r9 = fuzzvm.cr3,
                            10 => fuzzvm.regs.r10 = fuzzvm.cr3,
                            11 => fuzzvm.regs.r11 = fuzzvm.cr3,
                            12 => fuzzvm.regs.r12 = fuzzvm.cr3,
                            13 => fuzzvm.regs.r13 = fuzzvm.cr3,
                            14 => fuzzvm.regs.r14 = fuzzvm.cr3,
                            15 => fuzzvm.regs.r15 = fuzzvm.cr3,
                            _ => panic!("Unknown register in handling control regs"),
                        };
                    }
                    (1,8) => {
                        print!("mov from cr8: {:#x}\n", fuzzvm.get_rip());
                        /* mov from cr8 */

                        // Perf counter increment
                        stats::VMEXIT_MOV_XXX_CR8.fetch_add(1, Ordering::Acquire);

                        match (exit_qual >> 8) & 0xf {
                            0 => fuzzvm.regs.rax = 0x0,
                            1 => fuzzvm.regs.rcx = 0x0,
                            2 => fuzzvm.regs.rdx = 0x0,
                            3 => fuzzvm.regs.rbx = 0x0,
                            4 => fuzzvm.regs.rsp = 0x0,
                            5 => fuzzvm.regs.rbp = 0x0,
                            6 => fuzzvm.regs.rsi = 0x0,
                            7 => fuzzvm.regs.rdi = 0x0,
                            8 => fuzzvm.regs.r8 = 0x0,
                            9 => fuzzvm.regs.r9 = 0x0,
                            10 => fuzzvm.regs.r10 = 0x0,
                            11 => fuzzvm.regs.r11 = 0x0,
                            12 => fuzzvm.regs.r12 = 0x0,
                            13 => fuzzvm.regs.r13 = 0x0,
                            14 => fuzzvm.regs.r14 = 0x0,
                            15 => fuzzvm.regs.r15 = 0x0,
                            _ => panic!("Unknown register in handling control regs"),
                        };
                    }
                    (0,8) => {
                        /* mov to cr8 */
                        panic!("mov to cr8: {:#x}\n", fuzzvm.get_rip());
                        /*
                        let new_value = match (exit_qual >> 8) & 0xf {
                            0 => fuzzvm.regs.rax,
                            1 => fuzzvm.regs.rcx,
                            2 => fuzzvm.regs.rdx,
                            3 => fuzzvm.regs.rbx,
                            4 => fuzzvm.regs.rsp,
                            5 => fuzzvm.regs.rbp,
                            6 => fuzzvm.regs.rsi,
                            7 => fuzzvm.regs.rdi,
                            8 => fuzzvm.regs.r8,
                            9 => fuzzvm.regs.r9,
                            10 => fuzzvm.regs.r10,
                            11 => fuzzvm.regs.r11,
                            12 => fuzzvm.regs.r12,
                            13 => fuzzvm.regs.r13,
                            14 => fuzzvm.regs.r14,
                            15 => fuzzvm.regs.r15,
                            _ => panic!("Unknown register in handling control regs"),
                        };

                        if new_value == 0 {
                            fuzzvm.regs.print();
                            print!("Exit qual: {:#x}\n", exit_qual);
                            panic!("NEW CR3 is zero?!");
                        }
                        */
                    }
                    (2, _) => unimplemented!(),
                    (3, _) => unimplemented!(),
                    _ => {
                        print!("{} {} {}\n", instr_type, register, value);
                        fuzzvm.regs.print();
                        unimplemented!();
                    }
                }

                // Update RIP based on instruction length since we are handling the mov cr[38] 
                // instruction
                fuzzvm.update_rip();

                // Mark time for time in control registers
                stats::DEBUG_TIME_CONTROL_REGS.fetch_add(time::rdtsc() - timer_start_control_regs, 
                    Ordering::Acquire);
            }
            VmExitReason::MonitorTrapFlag => {
                // Monitor Trap Flag enabled aka single stepping
                // Perf counter increment
                stats::VMEXIT_MONITOR.fetch_add(1, Ordering::Acquire);

                // Call a custom fuzzer callback if provided with one
                fuzzvm.single_step_callback();

                // Trigger an alive core
                stats::set_alive_core(fuzzvm.core_id.into());
                
                // Preemption Timer triggered
                let timer_start_single_step = time::rdtsc();

                let curr_rip = fuzzvm.get_rip();
               
                // Log coverage if the current fuzzer wants to log coverage
                if fuzzvm.should_log_coverage() {
                    fuzzvm.trace.push(curr_rip);
                    fuzzvm.verbose_trace.push(fuzzvm.regs);

                    let count = fuzzvm.coverage.entry(fuzzvm.get_rip()).or_insert(0);
                    *count += 1;
                }

                // Mark time for Single Step
                stats::DEBUG_TIME_SINGLE_STEP.fetch_add(time::rdtsc() - timer_start_single_step,
                    Ordering::Acquire);
            }
            VmExitReason::RDMSR(msr) => {
                // Perf counter increment
                stats::VMEXIT_RDMSR.fetch_add(1, Ordering::Acquire);

                let timer_start_rdmsr = time::rdtsc();

                // Update return of RDMSR with the correct value from VBCPU
                match msr {
                    // IA32_GS_BASE => fuzzvm.regs.rax = fuzzvm.vbcpu.gs.base,
                    // IA32_KERNEL_GS_BASE => fuzzvm.regs.rax = fuzzvm.vbcpu.msr_kernel_gs_base,
                    IA32_KERNEL_GS_BASE => {
                        let kernel_gs_base = unsafe {
                            *fuzzvm.msrs.get(&fuzzvm.regs.rcx).expect("Unable to get msr for RDMSR")
                        };
                        fuzzvm.regs.rax  = kernel_gs_base & 0xffff_ffff;
                        fuzzvm.regs.rdx  = kernel_gs_base >> 32;
                    }
                    _ => {
                        use x86_64::registers::model_specific::Msr;
                        fuzzvm.regs.print();
                        fuzzvm.regs.rax =
                            unsafe { Msr::new((fuzzvm.regs.rcx & 0xffff_ffff) as u32).read() };
                        print!("   -> {:#x}\n", fuzzvm.regs.rax);
                        unimplemented!();
                    }
                }

                /* Update RIP past the RDMSR */
                fuzzvm.update_rip();

                // Mark time for VM reset in stats
                stats::DEBUG_TIME_RDMSR.fetch_add(time::rdtsc() - timer_start_rdmsr, Ordering::Acquire);
            }
            VmExitReason::WRMSR => {
                // Perf counter increment
                stats::VMEXIT_WRMSR.fetch_add(1, Ordering::Acquire);

                match fuzzvm.regs.rcx {
                    IA32_KERNEL_GS_BASE => {
                        let new_value = (fuzzvm.regs.rdx & 0xffff_ffff) << 32 
                                      | (fuzzvm.regs.rax & 0xffff_ffff);
                        fuzzvm.msrs.insert(fuzzvm.regs.rcx, new_value);

                        fuzzvm.vmwrite_msrs();
                    }
                    0x83f => {
                        if true {
                            match fuzzvm.regs.rax & 0xff {
                                0x1f => fuzzvm.inject_fault_1f(),
                                0x2f => fuzzvm.inject_fault_2f(),
                                _ => panic!("Unknown int to send via self-ipi: {:#x}", fuzzvm.regs.rax & 0xff)
                            };
                        }
                        fuzzvm.put_trace("selfipi.trace");
                        panic!("SELFIPI");
                    }
                    0x80b => {
                        // Just ignore EOI, since we were the ones that threw the interrupt to 
                        // begin with
                        fuzzvm.put_trace("eoi.trace");
                        panic!("EOI");
                    }
                    _ => {
                        fuzzvm.regs.print();
                        print!("Last user rip: {:#x}\n", last_user_rip);
                        // fuzzvm.put_trace("test.trace");
                        panic!("Unimplemented WRMSR found: {:#x}", fuzzvm.regs.rcx);
                    }
                }
                
                // Step over the WRMSR instruction
                fuzzvm.update_rip();
            }
            VmExitReason::CPUID => {
                fuzzvm.should_resume = false;
                // panic!("CPUID");

                /* Update RIP past the CPUID */
                // fuzzvm.update_rip();
            }
            VmExitReason::GDTRorIDTRAccess => {
                panic!("IN GDT/LGT HANDLER?");
            }
            VmExitReason::VMXPreemptionTimerExpired => {
                // Preemption Timer triggered
                // Perf counter increment
                stats::VMEXIT_PREEMPTION_TIMER.fetch_add(1, Ordering::Acquire);

                let timer_start_preempt = time::rdtsc();

                stats::TIMERS.fetch_add(1, Ordering::Acquire);

                // Just add the current RIP to the coverage map for now
                if fuzzvm.timer.is_none() { panic!("!! HIT PRE-TIMER WITH NO SET TIMER?! !!\n"); }

                fuzzvm.preemption_timer_count = fuzzvm.preemption_timer_count
                    .checked_add(1)
                    .expect("Overflow in preemption timer count");

                // Gather coverage based on the given fuzzer
                let _curr_rip = fuzzvm.get_rip();

                // Check if the current fuzzer wants to log the given RIP
                if fuzzvm.should_log_coverage() {
                    let count = fuzzvm.coverage.entry(fuzzvm.get_rip()).or_insert(0);
                    *count += 1;
                }

                // Reset the Timer in the guest
                vmwrite(VMCS_GUEST_PREEMPTION_TIMER_VALUE, fuzzvm.timer.unwrap());
                fuzzvm.should_resume = true;

                // Trigger an alive core
                stats::set_alive_core(fuzzvm.core_id.into());

                // Mark time for in preempt timer
                // stats::add_debug_time("preempt_timer", (time::rdtsc() - timer_start_preempt) as u64);
                stats::DEBUG_TIME_PREEMPT.fetch_add(time::rdtsc() - timer_start_preempt,
                    Ordering::Acquire);
            }
            VmExitReason::InitSignal => {
                // duration_timeout = time::future(fuzzvm.duration_timeout);
                // fuzzvm.tag = "-INIT".to_string();
                // fuzzvm.should_resume = false;
                // fuzzvm.set_preemption_timer_per_second(preemption_timer);
                panic!("[{}] Hit InitSignal\n", fuzzvm.core_id);
            }
            VmExitReason::RDTSCP => {
                // Set RDTSCP result to the fuzzvm accumulated result
                fuzzvm.regs.rax = fuzzvm.rdtsc & 0xffff_ffff;
                fuzzvm.regs.rdx = fuzzvm.rdtsc >> 32;
                fuzzvm.regs.rcx = 0;

                // Update past RDTSCP instruction
                fuzzvm.update_rip();
            }
            VmExitReason::RDTSC => {
                // Set RDTSC result to the fuzzvm accumulated result
                fuzzvm.regs.rax = fuzzvm.rdtsc & 0xffff_ffff;
                fuzzvm.regs.rdx = fuzzvm.rdtsc >> 32;

                // Update past RDTSC instruction
                fuzzvm.update_rip();
            }
            VmExitReason::VMCALL => {
                // Hit a VMCALL from the kernel fuzzer
                duration_timeout = time::future(fuzzvm.duration_timeout);
                if global_single_step {
                    fuzzvm.enable_single_step();
                } else {
                    fuzzvm.disable_single_step();
                }
                fuzzvm.set_preemption_timer_per_second(preemption_timer);
                fuzzvm.tag = "-VMCALL".to_string();
                stats::VMCALL_COUNT.fetch_add(1, Ordering::Acquire);
                fuzzvm.should_resume = false;
            }
            VmExitReason::EPTMisconfiguration => {
                fuzzvm.ept = unsafe { ept::ExtendedPageTable::new(&mut mm::PMEM) };
                fuzzvm.set_preemption_timer_per_second(preemption_timer);
                fuzzvm.should_resume = false;
            }
            _ => {
                print!("[{}] Unimplemented vmexit: {:?}\n", fuzzvm.core_id, vmexit_reason);
                print!("[{}] EXIT QUAL   - {:#x}\n", fuzzvm.core_id, exit_qual);
                break;
            }
        }

        // If we hit a timeout (time counter or instr), reset the guest and increment the 
        // timeout counter
        if !first_run {
            if duration_timeout < time::rdtsc()  && !fuzzvm.single_step {
                stats::DURATION_TIMEOUT_COUNT.fetch_add(1, Ordering::Acquire);
                duration_timeout = time::future(fuzzvm.duration_timeout);
                fuzzvm.should_resume = false;
                fuzzvm.tag = "-DUR".to_string();
                print!("DUR TIMEOUT: {:4.2} Minstrs\n", fuzzvm.executed_instrs as f64 / 1000.0 / 1000.0);
            }

            if fuzzvm.executed_instrs > fuzzvm.instruction_timeout {
                stats::INSTRUCTION_TIMEOUT_COUNT.fetch_add(1, Ordering::Acquire);
                duration_timeout = time::future(fuzzvm.duration_timeout);
                fuzzvm.should_resume = false;
                fuzzvm.tag = "-INS".to_string();
            }
        }


        // We have requested a VM reset.
        //
        // Reset the memory to the original VM memory by overwriting dirty pages
        // with their original contents.
        // Reset the register state to the original register state
        // Invalidate the EPT
        // Invalidate the VPID
        // Clear the single step trace
        if !fuzzvm.should_resume {
            // Insert the currently used file into the input corpus if it generated new coverage
            let timer_start_corp = time::rdtsc();

            if false {
                // Add the current coverage to the global coverage to see if we have anything new
                let mut cov = COVERAGE.lock();
                let mut found = Vec::new();
                let _cov_len = cov.len();
                for &addr in fuzzvm.coverage.keys() {
                    if cov.insert_addr(addr) {
                        found.push(addr);
                        fuzzvm.new_coverage = true;
                    }
                }
                drop(cov);
            }

            // Add executed instrs to running counter
            stats::DEBUG_TIME_CORPUS.fetch_add(time::rdtsc() - timer_start_corp, Ordering::Acquire); 

            // Inc fuzz counter if we finished a run
            stats::FUZZ_COUNT.fetch_add(1, Ordering::Acquire);
            match fuzzvm.core_id {
                1 => stats::FUZZ_COUNT_1.fetch_add(1, Ordering::Acquire),
                2 => stats::FUZZ_COUNT_2.fetch_add(1, Ordering::Acquire),
                3 => stats::FUZZ_COUNT_3.fetch_add(1, Ordering::Acquire),
                4 => stats::FUZZ_COUNT_4.fetch_add(1, Ordering::Acquire),
                _ => panic!("Unknown core_id for fuzz count"),
            };

            if cpu::is_bsp() {
                // Reset all stats after 1 minute to get better metrics
                if dry_run && time::rdtsc_elapsed(stats::START_TIME.load(Ordering::SeqCst) as u64) > 60.0 {
                    dry_run = false;
                    stats::reset();
                }
            }

            // Add executed instrs to running counter
            stats::EXECUTED_INSTRS.fetch_add(fuzzvm.executed_instrs, Ordering::Acquire); 

            // Call optional fuzzer specific code before fuzz
            fuzzvm.pre_fuzz_callback();

            // Reset the VM
            fuzzvm.reset();

            // Start timer for fuzz stats
            let timer_start_fuzz = time::rdtsc();

            // Fuzz the VM via the fuzzer
            fuzzvm.fuzz();

            // Increase fuzz time stats to global times
            stats::DEBUG_TIME_FUZZ.fetch_add(time::rdtsc() - timer_start_fuzz, Ordering::Acquire);

            // Call optional fuzzer specific code after fuzz
            fuzzvm.post_fuzz_callback();

            // Set single step status
            match fuzzvm.core_id {
                1 => stats::STATUS_1.store(fuzzvm.single_step as usize, Ordering::SeqCst),
                2 => stats::STATUS_2.store(fuzzvm.single_step as usize, Ordering::SeqCst),
                3 => stats::STATUS_3.store(fuzzvm.single_step as usize, Ordering::SeqCst),
                4 => stats::STATUS_4.store(fuzzvm.single_step as usize, Ordering::SeqCst),
                _ => panic!("Unknown core_id for status"),
            };

            // Reset timeout
            duration_timeout = time::future(fuzzvm.duration_timeout);

            // Reset preempt timer
            fuzzvm.set_preemption_timer_per_second(preemption_timer);

            // Reset fuzzvm tag for next run if applicable
            fuzzvm.tag.clear();

            // Reset single step
            if global_single_step {
                fuzzvm.enable_single_step();
            } else {
                fuzzvm.disable_single_step();
            }
        }
    }

    print!("[{}] \\o/ Infinite loop! \\o/\n", core_id);
    loop {}
}

/*
 * Magic Bochs breakpoint
 */
fn bochs_bp() {
    unsafe {
        llvm_asm!("xchg bx, bx"        :      // Assembly
              :      // Output
              :      // Input
              :      // Clobbered registers
             "volatile", "intel"); // Options
    }
}


