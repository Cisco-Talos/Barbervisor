use crate::time;
use crate::print;
use core::convert::TryInto;
use core::sync::atomic::{AtomicUsize, Ordering, AtomicU64};
use crate::{CORES, Cores, COVERAGE, MAX_CORES};
use crate::acpi;

lazy_static! {
    /// Number of fuzz cases that have been executed
    pub static ref FUZZ_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Fuzz count for core 1 
    pub static ref FUZZ_COUNT_1: AtomicUsize = AtomicUsize::new(0);
    /// Fuzz count for core 2
    pub static ref FUZZ_COUNT_2: AtomicUsize = AtomicUsize::new(0);
    /// Fuzz count for core 3 
    pub static ref FUZZ_COUNT_3: AtomicUsize = AtomicUsize::new(0);
    /// Fuzz count for core 4 
    pub static ref FUZZ_COUNT_4: AtomicUsize = AtomicUsize::new(0);

    /// Single step status for core 1 
    pub static ref STATUS_1: AtomicUsize = AtomicUsize::new(0);
    /// Single step status for core 2
    pub static ref STATUS_2: AtomicUsize = AtomicUsize::new(0);
    /// Single step status for core 3 
    pub static ref STATUS_3: AtomicUsize = AtomicUsize::new(0);
    /// Single step status for core 4 
    pub static ref STATUS_4: AtomicUsize = AtomicUsize::new(0);

    /// Number of crashes caught so far
    pub static ref CRASH_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Number of duration timeout cases so far
    pub static ref DURATION_TIMEOUT_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Number of instruction timeout cases so far
    pub static ref INSTRUCTION_TIMEOUT_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Number of cases that hit the HalInterrupt to exit
    pub static ref HAL_INTERRUPT_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Number of cases that hit VMCALL
    pub static ref VMCALL_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Time kernel started
    pub static ref START_TIME: AtomicUsize = AtomicUsize::new(0);

    /// Cores online
    pub static ref CORES_ONLINE: AtomicUsize = AtomicUsize::new(0);

    /// Single-core timing checks
    pub static ref VM_ONLINE:  AtomicUsize = AtomicUsize::new(0);

    /// Total clock cycles spent in the VM
    pub static ref CLOCK_CYCLES_IN_VM:  AtomicU64 = AtomicU64::new(0);

    /// Debug Times
    pub static ref DEBUG_TIME_PREEMPT: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_RDMSR: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_RESET: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_NONPAGE_RESET: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_VM: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_PRE_RUN: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_POST_RUN: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_PRINT_STATS: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_CONTROL_REGS: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_PRE_POST: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_SINGLE_STEP: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_EPT: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_ORIGINAL_PAGES_LOCK: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_BP: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_PF: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_FUZZ: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_CORPUS: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_NEXT_PACKET: AtomicU64 = AtomicU64::new(0);
    pub static ref DEBUG_TIME_NEXT_PACKET_COUNT: AtomicU64 = AtomicU64::new(0);

    /// Debug Times
    pub static ref EXECUTED_INSTRS: AtomicU64 = AtomicU64::new(0);
    pub static ref DURATION: AtomicU64 = AtomicU64::new(0);
    pub static ref TIMERS: AtomicU64 = AtomicU64::new(0);
    pub static ref PAGES_PER_RESET: AtomicU64 = AtomicU64::new(0);
    pub static ref INSTR_PER_CRASH: AtomicU64 = AtomicU64::new(0);

    /// VmExits 
    pub static ref VMEXIT_TOTAL: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_PAGE_FAULT: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_BREAKPOINT: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_DIVIDER: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_DEBUG: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_GENERAL_PROTECTION: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_INVALID_OPCODE: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_EPT: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_MOV_CR3_XXX: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_MOV_XXX_CR3: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_MOV_XXX_CR8: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_MONITOR: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_RDMSR: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_WRMSR: AtomicU64 = AtomicU64::new(0);
    pub static ref VMEXIT_PREEMPTION_TIMER: AtomicU64 = AtomicU64::new(0);

    pub static ref LAST_COVERAGE: AtomicU64 = AtomicU64::new(0);
}


/// Reset the Stats
pub fn reset() {
    // stats.vmexits.clear();
    START_TIME.store(time::rdtsc().try_into().unwrap(), Ordering::SeqCst);
    FUZZ_COUNT.store(0, Ordering::SeqCst);
    FUZZ_COUNT_1.store(0, Ordering::SeqCst);
    FUZZ_COUNT_2.store(0, Ordering::SeqCst);
    FUZZ_COUNT_3.store(0, Ordering::SeqCst);
    FUZZ_COUNT_4.store(0, Ordering::SeqCst);
    DEBUG_TIME_PREEMPT.store(0, Ordering::SeqCst);
    DEBUG_TIME_RDMSR.store(0, Ordering::SeqCst);
    DEBUG_TIME_RESET.store(0, Ordering::SeqCst);
    DEBUG_TIME_NONPAGE_RESET.store(0, Ordering::SeqCst);
    DEBUG_TIME_VM.store(0, Ordering::SeqCst);
    DEBUG_TIME_PRE_RUN.store(0, Ordering::SeqCst);
    DEBUG_TIME_POST_RUN.store(0, Ordering::SeqCst);
    DEBUG_TIME_PRINT_STATS.store(0, Ordering::SeqCst);
    DEBUG_TIME_CONTROL_REGS.store(0, Ordering::SeqCst);
    DEBUG_TIME_PRE_POST.store(0, Ordering::SeqCst);
    DEBUG_TIME_SINGLE_STEP.store(0, Ordering::SeqCst);
    DEBUG_TIME_EPT.store(0, Ordering::SeqCst);
    DEBUG_TIME_ORIGINAL_PAGES_LOCK.store(0, Ordering::SeqCst);
    DEBUG_TIME_BP.store(0, Ordering::SeqCst);
    DEBUG_TIME_PF.store(0, Ordering::SeqCst);
    DEBUG_TIME_FUZZ.store(0, Ordering::SeqCst);
    DEBUG_TIME_CORPUS.store(0, Ordering::SeqCst);
    EXECUTED_INSTRS.store(0, Ordering::SeqCst);
    VM_ONLINE.store(0, Ordering::SeqCst);
    DURATION_TIMEOUT_COUNT.store(0, Ordering::SeqCst);
    INSTRUCTION_TIMEOUT_COUNT.store(0, Ordering::SeqCst);
    TIMERS.store(0, Ordering::SeqCst);
    PAGES_PER_RESET.store(0, Ordering::SeqCst);
    INSTR_PER_CRASH.store(0, Ordering::SeqCst);
    DURATION.store(0, Ordering::SeqCst);

    VMEXIT_TOTAL.store(0, Ordering::SeqCst);
    VMEXIT_PAGE_FAULT.store(0, Ordering::SeqCst);
    VMEXIT_BREAKPOINT.store(0, Ordering::SeqCst);
    VMEXIT_DIVIDER.store(0, Ordering::SeqCst);
    VMEXIT_DEBUG.store(0, Ordering::SeqCst);
    VMEXIT_GENERAL_PROTECTION.store(0, Ordering::SeqCst);
    VMEXIT_INVALID_OPCODE.store(0, Ordering::SeqCst);
    VMEXIT_EPT.store(0, Ordering::SeqCst);
    VMEXIT_MOV_CR3_XXX.store(0, Ordering::SeqCst);
    VMEXIT_MOV_XXX_CR3.store(0, Ordering::SeqCst);
    VMEXIT_MOV_XXX_CR8.store(0, Ordering::SeqCst);
    VMEXIT_MONITOR.store(0, Ordering::SeqCst);
    VMEXIT_RDMSR.store(0, Ordering::SeqCst);
    VMEXIT_WRMSR.store(0, Ordering::SeqCst);
    VMEXIT_PREEMPTION_TIMER.store(0, Ordering::SeqCst);

    LAST_COVERAGE.store(0, Ordering::SeqCst);
}

pub fn set_alive_core(core: u64) {
    let old = CORES_ONLINE.load(Ordering::SeqCst);

    // There is a race here, but it's okay since it is just for cores online and it should catch 
    // up in time
    let new = old | 1 << core;
    CORES_ONLINE.store(new, Ordering::SeqCst);
}

/// Print the statistics that are not critical and only need to be seen periodically
pub fn print_debug() {
    let start_time = START_TIME.load(Ordering::SeqCst);
    let elapsed_time = time::rdtsc() as u64 - start_time as u64;
    let num_cores = if CORES == Cores::Single { 1 } else { MAX_CORES };

    let mut total: f64 = 1.0;
    let mut debug_str = alloc::string::String::new();

    print_red!("{:-^80}", " TIME PERCENTAGES ");
    let percent = DEBUG_TIME_VM.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "vm", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_RESET.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "page-reset", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_EPT.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:16} {:>6.3}%", "ept", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_PREEMPT.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "preempt", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_PRINT_STATS.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "print_stats", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_NONPAGE_RESET.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:16} {:>6.3}%", "nonpage-reset", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_FUZZ.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "fuzz input", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_RDMSR.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "rdmsr", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_CONTROL_REGS.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:16} {:>6.3}%", "control_regs", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_PRE_POST.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "pre_post", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_SINGLE_STEP.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "single_step", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_BP.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:16} {:>6.3}%", "bp", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_PF.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "pf", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_PRE_RUN.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "pre_run", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_POST_RUN.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:16} {:>6.3}%", "post_run", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);

    let percent = DEBUG_TIME_CORPUS.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    total -= percent;
    let result_str = format!("{:17} {:>6.3}% | ", "corpus", percent * 100.0);
    if debug_str.len() + result_str.len() > 80 { print!("{}\n", debug_str); debug_str.clear(); }
    debug_str.push_str(&result_str);
    print!("{}", debug_str); debug_str.clear(); 

    print!("{:17} {:>6.3}% | ", "unaccounted", total * 100.0);

    let percent = DEBUG_TIME_ORIGINAL_PAGES_LOCK.load(Ordering::Relaxed) as f64 / elapsed_time as f64 / num_cores as f64;
    print!("{:16} {:>6.3}%\n", "lock_stuck", percent * 100.0);

    /*
    let elapsed_time_secs = time::rdtsc_elapsed(start_time.try_into().unwrap());
    let mut vmexit_percent = 100.0;
    let total_vmexits = VMEXIT_TOTAL.load(Ordering::Relaxed);

    print_red!("{:-^80}", 
        format!(" VMEXITS {} (exit/sec {:8.2}) ", total_vmexits, 
            total_vmexits as f64 / num_cores as f64 / elapsed_time_secs)
    );
    let mut vmexit_str = alloc::string::String::new();

    let vmexit = VMEXIT_EPT.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "EPT", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_PREEMPTION_TIMER.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "TIMER", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_BREAKPOINT.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<15} {:7.4}%", "BP", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_MOV_CR3_XXX.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "mov cr3, xxx", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_MOV_XXX_CR3.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "mov xxx, cr3", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_MOV_XXX_CR8.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<15} {:7.4}%", "mov xxx, cr8", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_PAGE_FAULT.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "PF", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_DEBUG.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "DEBUG", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_DIVIDER.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<15} {:7.4}%", "DIV", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_GENERAL_PROTECTION.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "GP", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_INVALID_OPCODE.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "INV OPCODE", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_MONITOR.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<15} {:7.4}%", "SINGLE STEP", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_RDMSR.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "RDMSR", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let vmexit = VMEXIT_WRMSR.load(Ordering::Relaxed);
    let percent = vmexit as f64 / total_vmexits as f64 * 100.0;
    vmexit_percent -= percent;
    let result_str = format!("{:<16} {:7.4}% | ", "WRMSR", percent);
    if vmexit_str.len() + result_str.len() > 80 { print!("{}\n", vmexit_str); vmexit_str.clear(); }
    vmexit_str.push_str(&result_str);

    let result_str = format!("{:<15} {:7.4}%", "OTHER", vmexit_percent);
    vmexit_str.push_str(&result_str);

    // Push the remainder
    print!("{}\n", vmexit_str);
    */

    /*
    print!("Avg clock cycles per vm run {:2.2} {:2.2}Mcycles\n", 
        self.clock_cycles_in_vm.load(Ordering::SeqCst) as f64 
            / self.fuzz_count.load(Ordering::SeqCst) as f64,
        self.clock_cycles_in_vm.load(Ordering::SeqCst) as f64 
            / self.fuzz_count.load(Ordering::SeqCst) as f64 / 1000.0 / 1000.0
    );
    */
}

pub fn sec_to_time(seconds: u64) -> (u64, u64, u64) {
    let sec = seconds as u64 % 60;
    let min = seconds as u64 / 60;
    let hour = min as u64 / 60;
    (hour, min % 60, sec)
}

/// Display the statistics to the screen
pub fn print() {
    let start_time = START_TIME.load(Ordering::SeqCst);
    let fuzz_count = FUZZ_COUNT.load(Ordering::SeqCst);
    let curr_time = time::rdtsc_elapsed(start_time as u64);
    let (curr_time_hour, curr_time_min, curr_time_sec) = sec_to_time(curr_time as u64);

    let fuzz_count_per_sec = fuzz_count as f64 / time::rdtsc_elapsed(start_time.try_into().unwrap());
    // let cov_len = COVERAGE.lock().len();
    let cov_len = loop {
        match COVERAGE.try_lock() {
            Some(cov) => {
                break cov.len();
            }
            None => {
                print!("COVERAGE stats.rs LOCK\n");
            }
        }
    };

    let last_coverage = LAST_COVERAGE.load(Ordering::SeqCst);
    let (cov_time_hour, cov_time_min, cov_time_sec) = sec_to_time(time::rdtsc_elapsed(last_coverage as u64) as u64);

    let _instr_percent = INSTR_PER_CRASH.load(Ordering::SeqCst) as f64 
        / CRASH_COUNT.load(Ordering::SeqCst) as f64
        / 1_000_000.0;

    let _num_cores = if CORES == Cores::Single { 1 } else { MAX_CORES };
    let crash_count = CRASH_COUNT.load(Ordering::SeqCst);

    print_red!("{:-^80}", " STATS ");

    print!("{:<9}{:>16} | {:4} {:34} {:12}\n",
        "Time", format!("{:04}:{:02}:{:02}", curr_time_hour, curr_time_min, curr_time_sec),
        "Fuzz", format!("{:>8} [{:>6.3}/sec]", fuzz_count, fuzz_count_per_sec),
        if crash_count > 0 { r"/X\('-')/X\" } else { "" }
    );

    print!("{:<3}{:>22} | {:<9}{:>16} | {:<9}{:>15}\n",
        "Cov", format!("{} {:04}:{:02}:{:02}", cov_len, cov_time_hour, cov_time_min, cov_time_sec),
        "Crashes", format!("{:>7}", CRASH_COUNT.load(Ordering::SeqCst)),
        "MemFree", format!("{}MB", acpi::memory_stats() / 1000 / 1000)
    );

    print!("{:<9}{:>16} | {:<9}{:>16} | {:<9}{:>14}\n",
        // "Corpus", CORPUS.lock().len(),
        "Corpus", 0,
        "Inst/Run", format!("{:.4}M", EXECUTED_INSTRS.load(Ordering::SeqCst) as f64 / fuzz_count as f64 
                                        / 1_000_000.0),
        "Page/Reset", format!("{:.2}", PAGES_PER_RESET.load(Ordering::SeqCst) as f64 / fuzz_count as f64),
    );

    print!("{:<9}{:>16} | {:<9}{:>9} | {:<6}{:>25}\n",
        // "DurReset", format!("{:>6}", DURATION_TIMEOUT_COUNT.load(Ordering::SeqCst)),
        "VmCalls ", format!("{:>6}", VMCALL_COUNT.load(Ordering::SeqCst)),
        // "InsReset", format!("{:>6}", INSTRUCTION_TIMEOUT_COUNT.load(Ordering::SeqCst)),
        "HalReset", format!("{:>6}", HAL_INTERRUPT_COUNT.load(Ordering::SeqCst)),
        // We never have a core_id of 0, so we bit shift that bit away to avoid confusion
        "Cores", format!("{:025b}", CORES_ONLINE.load(Ordering::SeqCst) >> 1)
    );

    print!("{:<10}{:>15} | {:<9}{:>15} | {:<9}{:>15}\n",
        "DurReset", format!("{:>6}", DURATION_TIMEOUT_COUNT.load(Ordering::SeqCst)),
        "InsReset", format!("{:>6}", INSTRUCTION_TIMEOUT_COUNT.load(Ordering::SeqCst)),
        /*
        "Inst/Crash", format!("{:8.4}M", instr_percent),
        "Timers/Sec", format!("{:9.2}K", 
            TIMERS.load(Ordering::SeqCst) as f64 
            / curr_time
            / num_cores as f64
            / 1_000.0),
        */
        "Pkt", format!("{}", DEBUG_TIME_NEXT_PACKET_COUNT.load(Ordering::SeqCst))
    );

    let fuzz_count_1 =  FUZZ_COUNT_1.load(Ordering::SeqCst);
    let fuzz_count_2 =  FUZZ_COUNT_2.load(Ordering::SeqCst);
    let fuzz_count_3 =  FUZZ_COUNT_3.load(Ordering::SeqCst);
    let fuzz_count_4 =  FUZZ_COUNT_4.load(Ordering::SeqCst);

    let status_1 = if STATUS_1.load(Ordering::SeqCst) > 0 { "+" } else { "-" };
    let status_2 = if STATUS_2.load(Ordering::SeqCst) > 0 { "+" } else { "-" };
    let status_3 = if STATUS_3.load(Ordering::SeqCst) > 0 { "+" } else { "-" };
    let status_4 = if STATUS_4.load(Ordering::SeqCst) > 0 { "+" } else { "-" };

    print!("{:18} {:18} {:18} {:18}\n",
        format!("1 {}[{:>10.3}/sec]", status_1, fuzz_count_1 as f64 / curr_time),
        format!("2 {}[{:>10.3}/sec]", status_2, fuzz_count_2 as f64 / curr_time),
        format!("3 {}[{:>10.3}/sec]", status_3, fuzz_count_3 as f64 / curr_time),
        format!("4 {}[{:>10.3}/sec]", status_4, fuzz_count_4 as f64 / curr_time),
    );

    print!("\n");
    print!("\n");

    CORES_ONLINE.store(0, Ordering::SeqCst);
}
