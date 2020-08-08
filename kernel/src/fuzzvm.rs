#![allow(non_snake_case)]
#![allow(mutable_borrow_reservation_conflict)]

use crate::ept::*;
use crate::fuzzers::*;
use crate::net;
use crate::mm;
use crate::msr::*;
use crate::tools::*;
use crate::vmexit::*;
use crate::vmregs::{RFlags, Vbcpu, VmRegs};
use crate::vmx::*;
use crate::vmxflags::*;
use crate::msr_bitmap::MsrBitmap;
use crate::{HashMap, HashSet};
use crate::print;
use crate::{GuestPhysical, GuestVirtual, KernelPhysical};
use crate::stats;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::{String, FromUtf8Error, FromUtf16Error};
use spin::RwLock;
use x86_64::registers::model_specific::Msr;
use core::convert::TryInto;
use crate::time;
use crate::Rng;
use core::sync::atomic::Ordering;
use crate::coverage::CoverageType;
use crate::mutations::Mutation;
use crate::Files;

lazy_static! {
    /// Map of GuestPhysical to KernelPhysical 
    pub static ref ORIGINAL_PAGES: RwLock<HashMap<GuestPhysical, [u8; 0x1000]>> = RwLock::new(HashMap::with_capacity(50_000));
}

/// Main handler of a Fuzzable VM
pub struct FuzzVm<'a> {
    /// Original register state of the snapshot
    pub orig_regs: VmRegs,

    /// Current register state of the VM
    pub regs: VmRegs,

    /// Original CPU state from VirtualBox
    pub vbcpu: Vbcpu,

    /// VMXON page address for this VM
    pub vmxon_addr: u64,

    /// VMCS page address for this VM
    pub vmcs_addr: u64,

    /// Page Table for GuestVirtual to GuestPhysical addresses
    pub guest_virt_to_guest_phys_maps: HashMap<u64, HashMap<GuestVirtual, GuestPhysical>>,

    /// The Extended Page Table specific to this VM
    pub ept: ExtendedPageTable<'a, mm::Pmem>,

    /// Function used to fuzz the current VM
    pub fuzz_fn: Option<FuzzFunc>,

    /// Funtion used to return the input file from the current VM
    pub input_file_fn: Option<FuzzFileFunc>,

    /// Function called before the fuzzing function is called
    pub pre_fuzz_fn: Option<FuzzFunc>,

    /// Function called after the fuzzing function is called
    pub post_fuzz_fn: Option<FuzzFunc>,

    /// Function called after the fuzzing function is called
    pub stats_fn: Option<FuzzFunc>,

    /// Function called during single stepping
    pub single_step_fn: Option<FuzzFunc>,

    /// Kept copy of the current input file for the fuzz case
    pub input_file: Option<Vec<u8>>,

    /// List of mutations for the input file
    pub mutations: Option<Vec<Mutation>>,

    /// Should the VM be single stepping
    pub single_step: bool,

    /// Timer count to use for Preemption Timer. 
    /// Timer can be disabled with None
    pub timer: Option<u64>,

    /// Number of times preemption timer has fired
    pub preemption_timer_count: u64,

    /// Should the VM execute VMLAUNCH or VMRESUME
    pub should_resume: bool,

    /// VMExit can cause CR3 to be overwritten. This holds the current cr3 for the VM.
    pub cr3: u64,

    /// MSR Bitmaps address
    pub msr_bitmaps: MsrBitmap,

    /// Core ID that this VM is running under
    pub core_id: u32,

    /// MSRs used in the Fuzz run
    pub msrs: HashMap<u64, u64>,

    /// Address of MSR load page
    pub msr_load_page: u64,

    /// Address of MSR store page
    pub msr_store_page: u64,

    /// Blank address for MMIO addresses
    pub mmio_addr: u64,

    /// Rng for this VM
    pub rng: Rng,

    /// Vector of addresses to restart the VM if hit
    pub exit_breakpoints: Vec<GuestVirtual>,

    /// Trace specific to this VM
    pub trace: Vec<u64>,

    /// Trace specific to this VM
    pub verbose_trace: Vec<VmRegs>,

    /// Timeout for the VM in microseconds
    pub duration_timeout: u64,

    /// Timeout for the VM in instruction count
    pub instruction_timeout: u64,

    /// Virtual-APIC Page
    pub virtual_apic_addr: u64,

    /// APIC-access address 
    pub apic_access_addr: u64,

    /// All cr3s seen in execution
    pub cr3s: HashSet<u64>,

    /// Amount of time to offset the rdtsc count measured based on the instructions before vmlaunch
    vmlaunch_rdtsc: Option<u64>,

    /// Current rdtsc of the VM
    pub rdtsc: u64,

    /// Did we generate new coverage with this input?
    pub new_coverage: bool,

    /// Callback hooks currently in the VM
    pub hooks: HashMap<GuestVirtual, Box<dyn Fn(&mut FuzzVm)>>,

    /// Number of executed instructions in the VM based on the performance counters
    pub executed_instrs: u64,

    /// Type of coverage to gather for this VM
    pub coverage_type: CoverageType,

    /// Local coverage for the current fuzz run keyed (GuestVirtual, hit count)
    pub coverage: HashMap<u64, u64>,

    /// Utility tag used by various fuzzers
    pub tag: alloc::string::String,

    /// Database of file handles to File backings
    pub files: Files,
}


impl<'a> FuzzVm<'a> {
    pub fn new(
        vbcpu: Vbcpu,
        core_id: u32,
        fuzzer: impl Fuzzer,
    ) -> FuzzVm<'static> {
        let vbcpu = vbcpu;

        let vmxon_region = mm::alloc_page().expect("Failed to allocate VMXON region");
        let vmcs_addr = mm::alloc_page().expect("Failed to allocate VMCS region");
        let mmio_addr = mm::alloc_page().expect("Failed to allocate MMIO page").as_ptr() as u64;
        let ept = unsafe { ExtendedPageTable::new(&mut mm::PMEM) };

        let mut vmregs = VmRegs::from_vbcpu(&vbcpu);

        vmregs.guest_xsave_area_addr = mm::alloc_page().expect("Failed to allocate XSAVEAREA page")
            .as_ptr() as u64;

        vmregs.host_xsave_area_addr = mm::alloc_page().expect("Failed to allocate XSAVEAREA page")
            .as_ptr() as u64;

        // Sanity check to ensure the snapshot and fuzzer match
        assert!(fuzzer.start_rip() == vmregs.get_rip(),
            &format!("Fuzzer RIP {:#x} differs from Snapshot RIP {:#x}", fuzzer.start_rip(),
            vmregs.get_rip()));


        let single_step = true;
        let timer = None;

        // Remove the single step flag if still there from the snapshot
        let mut rflags = RFlags::from_bits_truncate(vmregs.rflags);
        rflags.remove(RFlags::TRAP);
        vmregs.rflags = rflags.bits();


        // Create the local page tables for local translation of GuestVirt to GuestPhys
        let mut maps = HashMap::new();
        let guest_virt_to_guest_phys = HashMap::new();
        maps.insert(vbcpu.cr3, guest_virt_to_guest_phys);

        let msr_load_page = mm::alloc_page().expect("Failed to allocate msr load page").as_ptr() as u64;
        let msr_store_page = mm::alloc_page().expect("Failed to allocate msr store page").as_ptr() as u64;

        let msrs = HashMap::new();

        // Initialize the list of exit breakpoints from the current fuzzer
        let exit_breakpoints: Vec<GuestVirtual> = fuzzer.exit_breakpoints().iter()
            .filter_map(|bp| if let Breakpoint::Virtual(addr) = bp { Some(*addr) } else { None })
            .collect();


        assert!(exit_breakpoints.len() == fuzzer.exit_breakpoints().len(), 
            "Fuzzer Exit breakpoints contained GuestPhysical breakpoint which isn't supported yet");

        let virtual_apic_addr = mm::alloc_page().expect("Failed to allocate virtual apic page")
            .as_ptr() as u64;

        let apic_access_addr = mm::alloc_page().expect("Failed to allocate apic access page")
            .as_ptr() as u64;


        // Initialize the FuzzVm struct
        let mut res = FuzzVm {
            orig_regs: vmregs.clone(),
            regs: vmregs,
            vbcpu,
            vmxon_addr: vmxon_region.as_mut_ptr() as u64,
            vmcs_addr: vmcs_addr.as_mut_ptr() as u64,
            guest_virt_to_guest_phys_maps: maps,
            ept,
            fuzz_fn: fuzzer.fuzz_fn(),
            input_file_fn: fuzzer.input_file_fn(),
            pre_fuzz_fn: fuzzer.pre_fuzz_fn(),
            post_fuzz_fn: fuzzer.post_fuzz_fn(),
            stats_fn: fuzzer.stats_fn(),
            single_step_fn: fuzzer.single_step_fn(),
            input_file: None,
            mutations: None,
            single_step,
            should_resume: false,
            cr3: vbcpu.cr3,
            msr_bitmaps: MsrBitmap::new(),
            core_id,
            msrs,
            msr_load_page,
            msr_store_page,
            mmio_addr,
            rng: Rng::new(),
            exit_breakpoints,
            trace: alloc::vec::Vec::new(),
            verbose_trace: alloc::vec::Vec::new(),
            timer,
            preemption_timer_count: 0,
            duration_timeout: fuzzer.duration_timeout(), 
            instruction_timeout: fuzzer.instruction_timeout(),
            virtual_apic_addr,
            apic_access_addr,
            cr3s: HashSet::new(),
            rdtsc: time::rdtsc(),
            vmlaunch_rdtsc:  None,
            new_coverage: false,
            hooks: HashMap::new(),
            executed_instrs: 0,
            coverage_type: fuzzer.coverage_type(),
            coverage: HashMap::new(),
            tag: alloc::string::String::new(),
            files: Files::new(),
        };

        // VMXON region only needs to be called once
        res.vmxon_region();

        // Map and set the breakpoints for exit conditions (only called once)
        res.set_exit_breakpoints(&fuzzer);

        // Map and set the breakpoints for exit conditions (only called once)
        res.set_hooks(&fuzzer);

        // Apply patches to the physical pages
        res.apply_patches(&fuzzer);

        // Init the FuzzVm
        res.init();

        res
    }

    /// Initializes VMCS and is called on each fuzz iteration
    pub fn init(&mut self) {
        self.create_vmcs();
        self.set_vmcs();
        self.set_vmcs_host();
        self.set_vmcs_guest();

        // Reset xsave area
        unsafe {
            let page = &mut *(self.regs.guest_xsave_area_addr as *mut [u8; 4096]);
            *page = [0; 4096];

            let page = &mut *(self.regs.host_xsave_area_addr as *mut [u8; 4096]);
            *page = [0; 4096];
        }

        // Init xsave area the same as the snapshot
        memcpy(self.regs.guest_xsave_area_addr as *mut u8, 
                self.vbcpu.xsave_state.as_ptr(), 
                self.vbcpu.xsave_state.len());

        // Reset apic area
        unsafe {
            let page = &mut *(self.virtual_apic_addr as *mut [u8; 4096]);
            *page = [0; 4096];

            let page = &mut *(self.apic_access_addr as *mut [u8; 4096]);
            *page = [0; 4096];
        }


        // Init MSRs
        self.msrs.clear();
        if self.vbcpu.msr_star != 0 { self.msrs.insert(IA32_STAR, self.vbcpu.msr_star); }
        if self.vbcpu.msr_lstar != 0 { self.msrs.insert(IA32_LSTAR, self.vbcpu.msr_lstar); }
        if self.vbcpu.msr_cstar != 0 { self.msrs.insert(IA32_CSTAR, self.vbcpu.msr_cstar); }
        if self.vbcpu.msr_sfmask != 0 { self.msrs.insert(IA32_SFMASK, self.vbcpu.msr_sfmask); }

        // Add perf counters to the VM
        self.msrs.insert(IA32_PERF_GLOBAL_CTRL as u64, 0x70000000f);
        self.msrs.insert(IA32_FIXED_CTR_CTRL as u64, 0x333);

        // Set SFMASK to reset all RFLAGs in SYSCALL to match REVEN at the moment
        self.msrs.insert(IA32_SFMASK, !2);
        if self.vbcpu.msr_kernel_gs_base != 0 { 
            self.msrs.insert(IA32_KERNEL_GS_BASE, self.vbcpu.msr_kernel_gs_base); 
        }
        self.vmwrite_msrs();
    }

    /// Execute the VM using the starting regs and memory
    pub fn run(&mut self) -> VmExitReason {
        let start_pre_run = time::rdtsc();

        let regs_addr = &(self.regs) as *const VmRegs as u64;

        if self.vmlaunch_rdtsc.is_none() {
            self.vmlaunch_rdtsc = Some(vmlaunch_pre_offset(self.regs.clone()));
        }

        stats::DEBUG_TIME_PRE_RUN.fetch_add(time::rdtsc() - start_pre_run, Ordering::Acquire);

        // Start timer for VM execution
        let start_vm = time::rdtsc();

        let vmexit_regs_addr = if self.should_resume { 
            self.vmresume_regs(regs_addr)
        } else {
            self.vmlaunch_regs(regs_addr)
        };

        // Calc stats timer for clock 
        let total_vm_time = time::rdtsc() - start_vm;

        let vmexit_regs: &VmRegs = unsafe { &*(vmexit_regs_addr as *const VmRegs) };

        // Performance metrics for time counter and instructions executed
        let rdtsc_before = vmexit_regs.rdtsc_high_before  << 32 | vmexit_regs.rdtsc_low_before;
        let rdtsc_after = vmexit_regs.rdtsc_high_after  << 32 | vmexit_regs.rdtsc_low_after;
        let vm_time = rdtsc_after - rdtsc_before;
        let retired_instructions = vmexit_regs.retired_instructions_high << 32 as u64
                                    | vmexit_regs.retired_instructions_low as u64;


        let exit_reason = VmExitReason::from_u64(vmread(VMCS_VMEXIT_REASON), &self.regs);

        // This 9 constant are the assembly around VMLAUNCH/VMRESUME that are not executed in the
        // vm. Subtract those out so we have a more accurate view of what the vm is doing.
        self.executed_instrs += retired_instructions.saturating_sub(10);
        let _pre_post_vmlaunch_time = total_vm_time - vm_time;
        // stats::CLOCK_CYCLES_IN_VM.fetch_add(vm_time, Ordering::Acquire);

        stats::DEBUG_TIME_VM.fetch_add(total_vm_time as u64, Ordering::Acquire);

        let start_post_run = time::rdtsc();

        // We always assume we will resume, unless we explicitly say to reset in a VmExit handler
        self.should_resume = true;

        // Bail if the VM caused an error from Abort Indicator
        if let AbortIndicator::Error(msg) = self.abort_indicator() {
            panic!("[{}] AbortError: {}\n", self.core_id, msg);
        }

        // Bail if the VM caused an error from Instruction Error
        if let InstructionError::Error(msg) = self.instruction_error() {
            panic!("[{}] InstrError: {}\n", self.core_id, msg);
        }

        // Update our regs with the saved context from the VmExit
        self.regs = *vmexit_regs;

        // Because there isn't a processor feature to exit on swapgs, our loaded KERNEL_GS_BASE
        // could be wrong if KERNEL_GS_BASE was overwritten and swapgs was called. 
        self.regs.gs_base = vmread(VMCS_GUEST_GS_BASE);


        // Save and rewrite the current KERNEL_GS_BASE
        let msr_store: VmExitStoreEntryMsr = unsafe { *(self.msr_store_page as *mut VmExitStoreEntryMsr) };

        self.regs.kernel_gs_base = msr_store.value;
        self.msrs.insert(IA32_KERNEL_GS_BASE, msr_store.value);
        self.vmwrite_msrs();

        stats::DEBUG_TIME_POST_RUN.fetch_add(time::rdtsc() - start_post_run, Ordering::Acquire);

        exit_reason
    }

    /// VMLAUNCH the VM with the given register state
    pub fn vmlaunch_regs(&mut self, regs_addr: u64) -> u64 {
        let start_time = time::rdtsc();

        unsafe {
            let mut result: u64;

           llvm_asm!(r#"
                # Save all registers since everything is clobbered
                push rbx
                push rcx
                push rdx
                push rbp
                push r8
                push r9
                push r10
                push r11
                push r12
                push r13
                push r14
                push r15
                pushf

                # Save the address of VmRegs for later use
                push rdi 

                # Set Guest RFLAGS from VmRegs
                mov rbx, [rdi + 8*18]
                or rbx, 2 # Must have 2 set in rflags
                mov rax, 0x6820
                vmwrite rax, rbx 

                # Set HOST RSP for when the guest VM VMEXITS
                mov rax, 0x6c14
                vmwrite rax, rsp

                # Set HOST RIP for when the guest VM VMEXITS
                mov rax, 0x6c16
                lea rbx, [rip + 1f]
                vmwrite rax, rbx

                #  Set CR2 for the guest
                mov rax, [rdi + 8*4]
                mov cr2, rax

                # Setup xcr0
                xor ecx, ecx
                xgetbv     # Load XCR0
                or eax, 7  # Enable AVX, SSE, X87
                # or eax, 0x1f  # Enable AVX, SSE, X87, BNDREG, BNDCSR
                # or eax, 0xff  # Enable AVX, SSE, X87, BNDREG, BNDCSR, AVX512
                xsetbv     # Save XCR0

                # Save the host xstate and restore the guest 
                mov rdx, 0xffffffffffffffff
                
                mov rbx, [rdi + 8*22] # host xstate
                xsave [rbx]
                mov rbx, [rdi + 8*21] # guest xstate
                xrstor [rbx]

                # Restore general purpose regs
                mov r8, [rdi + 8*8]
                mov r9, [rdi + 8*9]
                mov r10, [rdi + 8*10]
                mov r11, [rdi + 8*11]
                mov r12, [rdi + 8*12]
                mov r13, [rdi + 8*13]
                mov r14, [rdi + 8*14]
                mov r15, [rdi + 8*15]
                mov rbx, [rdi + 8*3]
                mov rbp, [rdi + 8*5]
                mov rsi, [rdi + 8*6]

                # Restore cr8
                # mov rax, [rdi + 8*29]
                # xor rax, rax
                # mov cr8, rax

                # Save the current timecounter
                rdtsc
                mov [rdi + 8*23], edx
                mov [rdi + 8*24], eax

                # Null the retired instructions counter
                mov rcx, 0x309
                xor edx, edx
                xor eax, eax
                wrmsr

                # Save the general purpose regs used in rdtsc
                mov rax, [rdi + 8*0]
                mov rdx, [rdi + 8*2]
                mov rcx, [rdi + 8*1]

                # Must be last since we are using RDI for VmRegs
                mov rdi, [rdi + 8*7] 

                vmlaunch

            1:
                # Get back address of registers
                # Exchange Guest RDI for address of VmRegs saved on the stack
                xchg rdi, [rsp]

                # Save off the guest registers about to be clobbered by rdmsr/rdtsc
                mov [rdi + 8*0], rax
                mov [rdi + 8*1], rcx
                mov [rdi + 8*2], rdx

                # Read Retired Instructions MSR
                mov rcx, 0x309
                rdmsr
                mov [rdi + 8*27], edx
                mov [rdi + 8*28], eax

                # Save the current timecounter after
                rdtsc
                mov [rdi + 8*25], edx
                mov [rdi + 8*26], eax

                # Save guest cr8
                # mov rax, cr8
                # mov [rdi + 8*29], rax

                mov [rdi + 8*3], rbx
                mov [rdi + 8*5], rbp
                mov [rdi + 8*6], rsi

                # Pop the Guest RDI that was just placed on the stack
                pop rax
                mov [rdi + 8*7], rax
                mov rax, cr2
                mov [rdi + 8*4], rax

                mov [rdi + 8*8], r8
                mov [rdi + 8*9], r9
                mov [rdi + 8*10], r10
                mov [rdi + 8*11], r11
                mov [rdi + 8*12], r12
                mov [rdi + 8*13], r13
                mov [rdi + 8*14], r14
                mov [rdi + 8*15], r15

                # Set Guest RSP in VmRegs
                mov rax, 0x681c
                vmread rbx, rax
                mov [rdi + 8*16], rbx

                # Set Guest RIP in VmRegs
                mov rax, 0x681e
                vmread rbx, rax 
                mov [rdi + 8*17], rbx
                
                # Set Guest RFLAGS in VmRegs
                mov rax, 0x6820
                vmread rbx, rax 
                mov [rdi + 8*18], rbx

                # Save the guest xstate and restore the host xstate
                mov rdx, 0xffffffffffffffff
                mov rax, 0xffffffffffffffff
                mov rbx, [rdi + 8*21] # guest xstate
                xsave [rbx]
                mov rbx, [rdi + 8*22] # host xstate
                xrstor [rbx]

                # Return address of VmRegs back from the assembly
                mov rax, rdi

                # Restore all registers since everything was clobbered
                popf
                pop r15
                pop r14
                pop r13
                pop r12
                pop r11
                pop r10
                pop r9
                pop r8
                pop rbp
                pop rdx
                pop rcx
                pop rbx
            "# 
            : /* output */   "={rax}"(result)
            : /* input */    "{rdi}"(regs_addr)
            : /* clobbers */ "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", 
                             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory", 
                             "cc"
            : /* options */ "volatile", "intel");

            let end_time = time::rdtsc();
            self.rdtsc += end_time - start_time - self.vmlaunch_rdtsc.unwrap();
            result
        }
    }

    /// VMRESUME the VM with the given register state
    pub fn vmresume_regs(&mut self, regs_addr: u64) -> u64 {
        let start_time = time::rdtsc();

        unsafe {
            let mut result: u64;

           llvm_asm!(r#"
                # Save all registers since everything is clobbered
                push rbx
                push rcx
                push rdx
                push rbp
                push r8
                push r9
                push r10
                push r11
                push r12
                push r13
                push r14
                push r15
                pushf

                # Save the address of VmRegs for later use
                push rdi 

                # Set Guest RFLAGS from VmRegs
                mov rbx, [rdi + 8*18]
                or rbx, 2 # Must have 2 set in rflags
                mov rax, 0x6820
                vmwrite rax, rbx 

                # Set RSP for when the guest VM VMEXITS
                mov rax, 0x6c14
                vmwrite rax, rsp

                # Set RIP for when the guest VM VMEXITS
                mov rax, 0x6c16
                lea rbx, [rip + 1f]
                vmwrite rax, rbx

                #  Set CR2 for the guest
                mov rax, [rdi + 8*4]
                mov cr2, rax

                # Setup xcr0
                xor ecx, ecx
                xgetbv     # Load XCR0
                or eax, 7  # Enable AVX, SSE, X87
                # or eax, 0x1f  # Enable AVX, SSE, X87, BNDREG, BNDCSR
                # or eax, 0xff  # Enable AVX, SSE, X87, BNDREG, BNDCSR, AVX512
                xsetbv     # Save XCR0

                # Save the host xstate and restore the guest 
                mov rdx, 0xffffffffffffffff
                mov rax, 0xffffffffffffffff
                mov rbx, [rdi + 8*22] # host xstate
                xsave [rbx]
                mov rbx, [rdi + 8*21] # guest xstate
                xrstor [rbx]

                # Restore general purpose regs
                mov r8, [rdi + 8*8]
                mov r9, [rdi + 8*9]
                mov r10, [rdi + 8*10]
                mov r11, [rdi + 8*11]
                mov r12, [rdi + 8*12]
                mov r13, [rdi + 8*13]
                mov r14, [rdi + 8*14]
                mov r15, [rdi + 8*15]
                mov rbx, [rdi + 8*3]
                mov rbp, [rdi + 8*5]
                mov rsi, [rdi + 8*6]

                # Restore guest cr8
                # mov rax, [rdi + 8*29]
                # mov cr8, rax
                # xor rax, rax

                # Save the current timecounter
                rdtsc
                mov [rdi + 8*23], edx
                mov [rdi + 8*24], eax

                # Zero out the retired instructions counter
                mov rcx, 0x309
                xor edx, edx
                xor eax, eax
                wrmsr

                # Save the general purpose regs used in rdtsc
                mov rax, [rdi + 8*0]
                mov rdx, [rdi + 8*2]
                mov rcx, [rdi + 8*1]

                # Must be last since we are using RDI for VmRegs
                mov rdi, [rdi + 8*7] 

                vmresume

            1:
                # Get back address of registers
                # Exchange Guest RDI for address of VmRegs saved on the stack
                xchg rdi, [rsp]

                # Save off the guest registers about to be clobbered by rdmsr/rdtsc
                mov [rdi + 8*0], rax
                mov [rdi + 8*1], rcx
                mov [rdi + 8*2], rdx

                # Read Retired Instructions MSR
                mov rcx, 0x309
                rdmsr
                mov [rdi + 8*27], edx
                mov [rdi + 8*28], eax

                # Save the current timecounter after
                rdtsc
                mov [rdi + 8*25], edx
                mov [rdi + 8*26], eax

                # Save guest cr8
                # mov rax, cr8
                # mov [rdi + 8*29], rax

                mov [rdi + 8*3], rbx
                mov [rdi + 8*5], rbp
                mov [rdi + 8*6], rsi

                # Pop the Guest RDI that was just placed on the stack
                pop rax
                mov [rdi + 8*7], rax
                mov rax, cr2
                mov [rdi + 8*4], rax

                mov [rdi + 8*8], r8
                mov [rdi + 8*9], r9
                mov [rdi + 8*10], r10
                mov [rdi + 8*11], r11
                mov [rdi + 8*12], r12
                mov [rdi + 8*13], r13
                mov [rdi + 8*14], r14
                mov [rdi + 8*15], r15

                # Set Guest RSP in VmRegs
                mov rax, 0x681c
                vmread rbx, rax
                mov [rdi + 8*16], rbx

                # Set Guest RIP in VmRegs
                mov rax, 0x681e
                vmread rbx, rax 
                mov [rdi + 8*17], rbx
                
                # Set Guest RFLAGS in VmRegs
                mov rax, 0x6820
                vmread rbx, rax 
                mov [rdi + 8*18], rbx

                # Save the guest xstate and restore the host xstate
                mov rdx, 0xffffffffffffffff
                mov rax, 0xffffffffffffffff
                mov rbx, [rdi + 8*21] # guest xstate
                xsave [rbx]
                mov rbx, [rdi + 8*22] # host xstate
                xrstor [rbx]

                # Return address of VmRegs back from the assembly
                mov rax, rdi

                # Restore all registers since everything was clobbered
                popf
                pop r15
                pop r14
                pop r13
                pop r12
                pop r11
                pop r10
                pop r9
                pop r8
                pop rbp
                pop rdx
                pop rcx
                pop rbx
            "# 
            : /* output */   "={rax}"(result)
            : /* input */    "{rdi}"(regs_addr)
            : /* clobbers */ "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", 
                             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory", 
                             "cc"
            : /* options */ "volatile", "intel");

            let end_time = time::rdtsc();
            self.rdtsc += end_time - start_time - self.vmlaunch_rdtsc.unwrap();
            result
        }
    }

    /// Checks and returns a human readble Abort Indicator
    fn abort_indicator(&self) -> AbortIndicator {
        let vmcs_region = self.vmcs_addr as *const VMCS;
        let abort_indicator = unsafe { (*vmcs_region).abort_indicator };
        match abort_indicator {
            0 => AbortIndicator::Success,
            1 => AbortIndicator::Error("There was a failure in saving guest MSRs (see Section 27.4)."),
            2 => AbortIndicator::Error("Host checking of the page-directory-pointer-table entries (PDPTEs) \
                                        failed (see Section 27.5.4)."),
            3 => AbortIndicator::Error("The current VMCS has been corrupted (through writes to the \
                                        corresponding VMCS region) in such a way that the logical processor \
                                        cannot complete the VM exit properly"),
            4 => AbortIndicator::Error("There was a failure on loading host MSRs (see Section 27.6)."),
            5 => AbortIndicator::Error("There was a machine-check event during VM exit (see Section 27.8)."),
            6 => AbortIndicator::Error("The logical processor was in IA-32e mode before the VM exit and the \
                                        host address-space size VM-entry control was 0 (see Section 27.5)."),
            _ => unimplemented!()
        }
    }

    /// Checks and returns a human readble Instruction Error
    fn instruction_error(&self) -> InstructionError {
        // Taken from Table 30-1 VM-Instruction Error Numbers
        // Intel Vol 3 - 30.4
        match vmread(VMCS_VM_INSTRUCTION_ERROR) {
            0 => InstructionError::Success,
            1 => InstructionError::Error("VMCALL executed in VMX root operation"),
            2 => InstructionError::Error("VMCLEAR with invalid physical address"),
            3 => InstructionError::Error("VMCLEAR with VMXON pointer"),
            4 => InstructionError::Error("VMLAUNCH with non-clear VMCS"),
            5 => InstructionError::Error("VMRESUME with non-launched VMCS"),
            6 => InstructionError::Error("VMRESUME after VMXOFF (VMXOFF and VMXON between VMLAUNCH and \
                                          VMRESUME)"),
            7 => InstructionError::Error("VM entry with invalid control field(s)"),
            8 => InstructionError::Error("VM entry with invalid host-state field(s)"),
            9 => InstructionError::Error("VMPTRLD with invalid physical address"),
            10 => InstructionError::Error("VMPTRLD with VMXON pointer"),
            11 => InstructionError::Error("VMPTRLD with incorrect VMCS revision identifier"),
            12 => InstructionError::Error("VMREAD/VMWRITE from/to unsupported VMCS component"),
            13 => InstructionError::Error("VMWRITE to read-only VMCS component"),
            15 => InstructionError::Error("VMXON executed in VMX root operation"),
            16 => InstructionError::Error("VM entry with invalid executive-VMCS pointer"),
            17 => InstructionError::Error("VM entry with non-launched executive VMCS"),
            18 => InstructionError::Error("VM entry with executive-VMCS pointer not VMXON pointer \
                                          (when attempting to deactivate the dual-monitor treatment \
                                           of SMIs and SMM)"),
            19 => InstructionError::Error("VMCALL with non-clear VMCS (when attempting to activate the \
                                           dual-monitor treatment of SMIs and SMM)"),
            20 => InstructionError::Error("VMCALL with invalid VM-exit control fields"),
            22 => InstructionError::Error("VMCALL with incorrect MSEG revision identifier (when attempting \
                                           to activate the dual-monitor treatment of SMIs and SMM)"),
            23 => InstructionError::Error("VMXOFF under dual-monitor treatment of SMIs and SMM"),
            24 => InstructionError::Error("VMCALL with invalid SMM-monitor features (when attempting to \
                                           activate the dual-monitor treatment of SMIs and SMM)"),
            25 => InstructionError::Error("VM entry with invalid VM-execution control fields in executive \
                                           VMCS (when attempting to return from SMM)"),
            26 => InstructionError::Error("VM entry with events blocked by MOV SS."),
            28 => InstructionError::Error("Invalid operand to INVEPT/INVVPID."),
            _ => unimplemented!()
        }
    }

    /// Internal function to initialize VMXON region
    fn vmxon_region(&self) {
        let vmxon_struct = self.vmxon_addr as *mut VmxOn;
        let vmx_basic = unsafe { Msr::new(IA32_VMX_BASIC).read() };

        let revision_id = (vmx_basic & 0x7fff_ffff) as u32;
        unsafe {
            (*vmxon_struct).revision_id = revision_id;
        }
        vmxon(self.vmxon_addr);
    }

    /// Internal function to initialize VMCS
    pub fn create_vmcs(&self) {
        let vmcs_region = self.vmcs_addr as *mut VMCS;
        let vmx_basic = unsafe { Msr::new(IA32_VMX_BASIC).read() };

        let revision_id = (vmx_basic & 0x7fff_ffff) as u32;
        unsafe {
            (*vmcs_region).revision_id = revision_id;
        }
        vmclear(self.vmcs_addr);
        vmptrld(self.vmcs_addr);
    }

    /// Isolate the ProcBased controls so we can trigger MonitorTrap flags on and off easier
    fn set_procbased_flags(&self) {
        let procbased_or = ProcCtls::read_raw() & 0xffff_ffff;
        let procbased_and = ProcCtls::read_raw() >> 32;
        let mut procbased_ctls = ProcCtlsFlags::empty();
        procbased_ctls.insert(ProcCtlsFlags::SECONDARY);
        procbased_ctls.insert(ProcCtlsFlags::CR3_STORE_EXIT);
        procbased_ctls.insert(ProcCtlsFlags::CR3_LOAD_EXIT);
        // procbased_ctls.insert(ProcCtlsFlags::CR8_STORE_EXIT); // mov cr8, XXX
        // procbased_ctls.insert(ProcCtlsFlags::CR8_LOAD_EXIT);  // mov XXX, cr8
        if self.single_step {
            procbased_ctls.insert(ProcCtlsFlags::MONITOR_TRAP);
        }
        procbased_ctls.insert(ProcCtlsFlags::USE_MSR_BITMAPS);
        // procbased_ctls.insert(ProcCtlsFlags::RDTSC_EXIT);
        procbased_ctls.insert(ProcCtlsFlags::USE_TPR_SHADOW);
        vmwrite(
            VMCS_PROC_BASED_VMEXEC_CTL,
            (procbased_ctls.bits() as u64 | procbased_or) & procbased_and
        );
    }

    /// Set fields in the VMCS for this VM
    fn set_vmcs(&self) {
        self.set_procbased_flags();

        // Enable EPT and UNRESTRICTED GUEST
        let procbased2_or = ProcCtls2::read_raw() & 0xffff_ffff;
        let procbased2_and = ProcCtls2::read_raw() >> 32;
        let mut procbased2_ctls = ProcCtls2Flags::empty();
        procbased2_ctls.insert(ProcCtls2Flags::ENABLE_EPT);
        procbased2_ctls.insert(ProcCtls2Flags::UNRESTRICTED_GUEST);
        procbased2_ctls.insert(ProcCtls2Flags::ENABLE_RDTSCP); 
        procbased2_ctls.insert(ProcCtls2Flags::ENABLE_VPID);
        procbased2_ctls.insert(ProcCtls2Flags::ENABLE_INVPCID); 
        // procbased2_ctls.insert(ProcCtls2Flags::ENABLE_XSAVES_XRSTORS);
        
        let entry_or = EntryCtls::read_raw() & 0xffff_ffff;
        let entry_and = EntryCtls::read_raw() >> 32;
        let mut entry_ctls = EntryCtlsFlags::empty();
        if self.vbcpu.msr_efer >> 8 & 1 == 1 {
            // print!("64 bit guest!\n");
            entry_ctls.insert(EntryCtlsFlags::IA32_MODE_GUEST);
        } else {
            panic!("32 bit guest not implemented!\n")
        }


        let exit_or = ExitCtls::read_raw() & 0xffff_ffff;
        let exit_and = ExitCtls::read_raw() >> 32;
        let mut exit_ctls = ExitCtlsFlags::empty();
        exit_ctls.insert(ExitCtlsFlags::HOST_ADDRESS_SPACE_SIZE);
        if self.timer.is_some() {
            exit_ctls.insert(ExitCtlsFlags::SAVE_VMX_PREEMPTION_TIMER_VALUE);
        }

        // !!! Be sure to load EFER to enable SYSCALL !!! 
        entry_ctls.insert(EntryCtlsFlags::LOAD_IA32_EFER);

        let pin_ctrls_or = PinCtls::read_raw() & 0xffff_ffff;
        let pin_ctrls_and = PinCtls::read_raw() >> 32;
        let mut pin_ctls = PinCtlsFlags::empty();
        if self.timer.is_some() {
            pin_ctls.insert(PinCtlsFlags::ACTIVE_VMX_PREEMPTION_TIMER);
        }

        /* Enable Virtual APIC */
        procbased2_ctls.insert(ProcCtls2Flags::VIRTUALIZE_APIC);
        // procbased2_ctls.insert(ProcCtls2Flags::VIRTUALIZE_X2APIC_MODE);
        procbased2_ctls.insert(ProcCtls2Flags::VIRTUAL_INTERRUPT_DELIVERY);
        procbased2_ctls.insert(ProcCtls2Flags::APIC_REGISTER_VIRTUALIZATION);

        // Init VMCS control flags
        vmwrite(VMCS_PIN_BASED_VMEXEC_CTL, 
            (pin_ctls.bits() as u64 | pin_ctrls_or) & pin_ctrls_and);

        vmwrite(
            VMCS_SECONDARY_VMEXEC_CTL,
            (procbased2_ctls.bits() as u64 | procbased2_or) & procbased2_and,
        );

        vmwrite(
            VMCS_VMENTRY_CTL,
            (entry_ctls.bits() as u64 | entry_or) & entry_and,
        );

        vmwrite(
            VMCS_VMEXIT_CTL,
            (exit_ctls.bits() as u64 | exit_or) & exit_and,
        );

        vmwrite(VMCS_ADDR_IO_BITMAP_A, 0xffff_ffff);
        vmwrite(VMCS_ADDR_IO_BITMAP_A_HIGH, 0xffff_ffff);
        vmwrite(VMCS_ADDR_IO_BITMAP_B, 0xffff_ffff);
        vmwrite(VMCS_ADDR_IO_BITMAP_B_HIGH, 0xffff_ffff);

        vmwrite(VMCS_GUEST_IA32_PAT, self.vbcpu.msr_pat & 0xffff_ffff);
        vmwrite(VMCS_GUEST_IA32_PAT_HIGH, self.vbcpu.msr_pat >> 32);

        // Extended Features Flag (contains enabling SYSCALL)
        vmwrite(VMCS_GUEST_IA32_EFER, self.vbcpu.msr_efer & 0xffff_ffff);
        vmwrite(VMCS_GUEST_IA32_EFER_HIGH, self.vbcpu.msr_efer >> 32);

        vmwrite(VMCS_EXEC_VMCS_PTR, 0);
        vmwrite(VMCS_EXEC_VMCS_PTR_HIGH, 0);
        vmwrite(VMCS_TSC_OFFSET, 0);
        vmwrite(VMCS_TSC_OFFSET_HIGH, 0);

        /* Setup Virutal APIC */
        vmwrite(VMCS_VIRTUAL_APIC, self.virtual_apic_addr);
        vmwrite(VMCS_VIRTUAL_APIC_HIGH, self.virtual_apic_addr >> 32);
        vmwrite(VMCS_APIC_ACCESS, self.apic_access_addr);
        vmwrite(VMCS_APIC_ACCESS_HIGH, self.apic_access_addr >> 32);

        /* Setup EPT */
        let eptp = EPTP::new(self.ept.get_backing() as u64);
        vmwrite(VMCS_EPT_PTR, eptp.as_ptr());
        vmwrite(VMCS_EPT_PTR_HIGH, eptp.as_ptr() >> 32);

        /* Setup MSR Bitmap */
        // Manual: 24.6.9 MSR-Bitmap Address
        /* Don't VMEXIT on 0xe7, 0xe8 */
        // self.msr_bitmaps.enable_all();
        self.msr_bitmaps.disable_all();

        // self.msr_bitmaps.clear_read(0xe7);
        // self.msr_bitmaps.clear_read(0xe8);
        // self.msr_bitmaps.clear_write(0xe7);
        // self.msr_bitmaps.clear_write(0xe8);

        /* ONLY VMEXIT on MSRs that have to be loaded in the load area */
        // self.msr_bitmaps.set_read(IA32_STAR);
        // self.msr_bitmaps.set_read(IA32_LSTAR);
        // self.msr_bitmaps.set_read(IA32_CSTAR);
        // self.msr_bitmaps.set_read(IA32_SFMASK);
        self.msr_bitmaps.set_read(IA32_KERNEL_GS_BASE);
        // self.msr_bitmaps.set_write(IA32_STAR);
        // self.msr_bitmaps.set_write(IA32_LSTAR);
        // self.msr_bitmaps.set_write(IA32_CSTAR);
        // self.msr_bitmaps.set_write(IA32_SFMASK);
        self.msr_bitmaps.set_write(IA32_KERNEL_GS_BASE);
        
        self.msr_bitmaps.set_write(0x83f);
        self.msr_bitmaps.set_write(0x80b);

        vmwrite(VMCS_MSR_BITMAP_LOW, self.msr_bitmaps.get_backing() & 0xffff_ffff);
        vmwrite(VMCS_MSR_BITMAP_HIGH, self.msr_bitmaps.get_backing() >> 32);

        /* EXCEPTIONS HERE */
        vmwrite(VMCS_EXCEPTION_BITMAP, 0xffff_ffff ); // handle all exceptions
        // vmwrite(VMCS_EXCEPTION_BITMAP, 0); // handle no exceptions
        // vmwrite(VMCS_EXCEPTION_BITMAP, 
            // 0xffff_ffff & !(1 << ExceptionVector::PageFault as u64) ); // handle blacklist exceptions
        // vmwrite(VMCS_EXCEPTION_BITMAP, 1 << ExceptionVector::Breakpoint as u64 | 
                                       // 1 << ExceptionVector::InvalidOpcode as u64 | 
                                       // 1 << ExceptionVector::GeneralProtection as u64); // handle some exceptions
        

        /* Page fault bits */ 
        vmwrite(VMCS_PAGEFAULT_ERRCODE_MASK, 0);
        // vmwrite(VMCS_PAGEFAULT_ERRCODE_MATCH, 0xffffffff); // Do exit on page faults
        vmwrite(VMCS_PAGEFAULT_ERRCODE_MATCH, 0); // Don't exit on page faults

        // Enable timer if timer is currently set
        if let Some(timer_val) = self.timer {
            assert!(timer_val > 0);
            vmwrite(VMCS_GUEST_PREEMPTION_TIMER_VALUE, timer_val);
        }

        vmwrite(VMCS_CR3_TARGET_COUNT, 0);

        vmwrite(VMCS_VMENTRY_INTERRUPTION_INFO_FIELD, 0);
        vmwrite(VMCS_VMENTRY_EXCEPTION_ERRCODE, 0);
        vmwrite(VMCS_VMENTRY_INSTRUCTION_LENGTH, 0);

        vmwrite(VMCS_TPR_THRESHOLD, 0);

        vmwrite(VMCS_CR0_GUESTHOST_MASK, 0);
        vmwrite(VMCS_CR4_GUESTHOST_MASK, 0);
        vmwrite(VMCS_CR0_READ_SHADOW, 0);
        vmwrite(VMCS_CR4_READ_SHADOW, 0);

        vmwrite(VMCS_CR3_TARGET_VALUE_0, 0);
        vmwrite(VMCS_CR3_TARGET_VALUE_1, 0);
        vmwrite(VMCS_CR3_TARGET_VALUE_2, 0);
        vmwrite(VMCS_CR3_TARGET_VALUE_3, 0);

        /* Write all the MSRs pulled from the VBCPU */
        self.vmwrite_msrs();

        let store_msrs = vec![IA32_KERNEL_GS_BASE];
        for (i, msr) in store_msrs.iter().enumerate() {
            let curr_addr = self.msr_store_page + (i * 16) as u64;
            let mut msr_store = curr_addr as *mut VmExitStoreEntryMsr;

            unsafe {
                (*msr_store).msr = *msr;
            }
        }

        vmwrite(VMCS_VMEXIT_MSR_STORE_ADDR, self.msr_store_page & 0xffff_ffff);
        vmwrite(VMCS_VMEXIT_MSR_STORE_ADDR_HIGH, self.msr_store_page >> 32);
        vmwrite(VMCS_VMEXIT_MSR_STORE_COUNT, store_msrs.len() as u64);

        vmwrite(VMCS_VPID, (self.core_id).into());
    }

    /// Set the host specific fields in the VMCS
    fn set_vmcs_host(&self) {
        let host_regs = get_vmcs_host_regs();

        // RPL and TI in the segment selector must be 0
        vmwrite(VMCS_HOST_ES_SEL, host_regs.es.sel as u64);
        vmwrite(VMCS_HOST_CS_SEL, host_regs.cs.sel as u64);
        vmwrite(VMCS_HOST_SS_SEL, host_regs.ss.sel as u64);
        vmwrite(VMCS_HOST_DS_SEL, host_regs.ds.sel as u64);
        vmwrite(VMCS_HOST_FS_SEL, host_regs.fs.sel as u64);
        vmwrite(VMCS_HOST_GS_SEL, host_regs.gs.sel as u64);
        vmwrite(VMCS_HOST_TR_SEL, host_regs.cs.sel as u64);

        vmwrite(VMCS_HOST_CR0, host_regs.cr0);
        vmwrite(VMCS_HOST_CR3, host_regs.cr3);
        vmwrite(VMCS_HOST_CR4, host_regs.cr4);

        vmwrite(VMCS_HOST_FS_BASE, host_regs.fs.base as u64);
        vmwrite(VMCS_HOST_GS_BASE, host_regs.gs.base as u64);
        vmwrite(VMCS_HOST_TR_BASE, host_regs.tr.base as u64);
        vmwrite(VMCS_HOST_GDTR_BASE, host_regs.gdtr.base as u64);
        vmwrite(VMCS_HOST_IDTR_BASE, host_regs.idtr.base as u64);

        vmwrite(VMCS_HOST_SYSENTER_ESP, 0xdead1111);
        vmwrite(VMCS_HOST_SYSENTER_EIP, 0xdead2222);
    }

    /// Set the guest specific fields in the VMCS
    pub fn set_vmcs_guest(&self) {
        vmwrite(VMCS_GUEST_CS_BASE, self.vbcpu.cs.base);
        vmwrite(VMCS_GUEST_CS_SEL, self.vbcpu.cs.sel.into());
        vmwrite(VMCS_GUEST_CS_LIMIT, self.vbcpu.cs.limit.into());
        vmwrite(
            VMCS_GUEST_CS_ACCESS_RIGHTS,
            self.vbcpu.cs.access_rights.into(),
        );

        vmwrite(VMCS_GUEST_DS_SEL, self.vbcpu.ds.sel.into());
        vmwrite(VMCS_GUEST_DS_LIMIT, self.vbcpu.ds.limit.into());
        vmwrite(
            VMCS_GUEST_DS_ACCESS_RIGHTS,
            self.vbcpu.ds.access_rights.into(),
        );

        vmwrite(VMCS_GUEST_ES_SEL, self.vbcpu.es.sel.into());
        vmwrite(VMCS_GUEST_ES_LIMIT, self.vbcpu.es.limit.into());
        vmwrite(
            VMCS_GUEST_ES_ACCESS_RIGHTS,
            self.vbcpu.es.access_rights.into(),
        );

        vmwrite(VMCS_GUEST_SS_SEL, self.vbcpu.ss.sel.into());
        vmwrite(VMCS_GUEST_SS_LIMIT, self.vbcpu.ss.limit.into());
        vmwrite(
            VMCS_GUEST_SS_ACCESS_RIGHTS,
            self.vbcpu.ss.access_rights.into(),
        );

        vmwrite(VMCS_GUEST_FS_SEL, self.vbcpu.fs.sel.into());
        vmwrite(VMCS_GUEST_FS_LIMIT, self.vbcpu.fs.limit.into());
        vmwrite(
            VMCS_GUEST_FS_ACCESS_RIGHTS,
            self.vbcpu.fs.access_rights.into(),
        );

        vmwrite(VMCS_GUEST_GS_SEL, self.vbcpu.gs.sel.into());
        vmwrite(VMCS_GUEST_GS_LIMIT, self.vbcpu.gs.limit.into());
        vmwrite(
            VMCS_GUEST_GS_ACCESS_RIGHTS,
            self.vbcpu.gs.access_rights.into(),
        );

        vmwrite(VMCS_GUEST_LDTR_SEL, self.vbcpu.ldtr.sel.into());
        vmwrite(VMCS_GUEST_LDTR_LIMIT, self.vbcpu.ldtr.limit.into());
        vmwrite(
            VMCS_GUEST_LDTR_ACCESS_RIGHTS,
            self.vbcpu.ldtr.access_rights.into(),
        );

        vmwrite(VMCS_GUEST_TR_SEL, self.vbcpu.tr.sel.into());
        vmwrite(VMCS_GUEST_TR_LIMIT, self.vbcpu.tr.limit.into());
        vmwrite(
            VMCS_GUEST_TR_ACCESS_RIGHTS,
            self.vbcpu.tr.access_rights.into(),
        );

        vmwrite(VMCS_GUEST_GDTR_BASE, self.vbcpu.gdtr_addr);
        vmwrite(VMCS_GUEST_GDTR_LIMIT, self.vbcpu.gdtr_cb.into());

        vmwrite(VMCS_GUEST_IDTR_BASE, self.vbcpu.idtr_addr);
        vmwrite(VMCS_GUEST_IDTR_LIMIT, self.vbcpu.idtr_cb.into());

        vmwrite(VMCS_VMCS_LINK_PTR, 0xffff_ffff);
        vmwrite(VMCS_VMCS_LINK_PTR_HIGH, 0xffff_ffff);

        vmwrite(VMCS_GUEST_IA32_DEBUGCTL, 0);
        vmwrite(VMCS_GUEST_IA32_DEBUGCTL_HIGH, 0);

        vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
        vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);

        // FROM VMX-FIXED BITS IN CR0 A.8
        let cr0_fixed0 = unsafe { Msr::new(IA32_VMX_CR0_FIXED0).read() };
        let cr0_fixed1 = unsafe { Msr::new(IA32_VMX_CR0_FIXED1).read() };
        let mut cr0 = self.vbcpu.cr0;
        cr0 &= cr0_fixed1;
        cr0 |= cr0_fixed0;
        vmwrite(VMCS_GUEST_CR0, cr0);
        // print!("Cr0: {:032b}\n", cr0);
        // print!("Host Cr0: {:032b}\n", Cr0::read().bits());

        // Write guest CR3
        vmwrite(VMCS_GUEST_CR3, self.cr3);

        // FROM VMX-FIXED BITS IN CR4 A.8
        let cr4_fixed0 = unsafe { Msr::new(IA32_VMX_CR4_FIXED0).read() };
        let cr4_fixed1 = unsafe { Msr::new(IA32_VMX_CR4_FIXED1).read() };
        let mut cr4 = self.vbcpu.cr4;
        cr4 &= cr4_fixed1;
        cr4 |= cr4_fixed0;
        vmwrite(VMCS_GUEST_CR4, cr4);

        vmwrite(VMCS_GUEST_ES_BASE, self.vbcpu.es.base);
        vmwrite(VMCS_GUEST_SS_BASE, self.vbcpu.ss.base);
        vmwrite(VMCS_GUEST_DS_BASE, self.vbcpu.ds.base);
        vmwrite(VMCS_GUEST_FS_BASE, self.vbcpu.fs.base);
        vmwrite(VMCS_GUEST_GS_BASE, self.vbcpu.gs.base);
        vmwrite(VMCS_GUEST_LDTR_BASE, self.vbcpu.ldtr.base);
        vmwrite(VMCS_GUEST_TR_BASE, self.vbcpu.tr.base);

        vmwrite(VMCS_GUEST_DR7, 0);

        vmwrite(VMCS_GUEST_SYSENTER_ESP, self.vbcpu.sysenter_esp); 
        vmwrite(VMCS_GUEST_SYSENTER_EIP, self.vbcpu.sysenter_eip); 
        vmwrite(VMCS_GUEST_SYSENTER_CS, self.vbcpu.sysenter_cs); 

        vmwrite(VMCS_GUEST_RSP, self.regs.rsp);
        vmwrite(VMCS_GUEST_RIP, self.get_rip()); 

        let RFLAGS_ALWAYS1_BIT = 0x2;
        vmwrite(VMCS_GUEST_RFLAGS, RFLAGS_ALWAYS1_BIT | self.regs.rflags);
        vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
    }

    /// Maps the the passed in GUEST VM address to the address of a newly allocated page
    pub fn map_addr(&mut self, address: GuestPhysical, flags: EptFlags) -> KernelPhysical {
        // Wanted address isn't mapped into the VM yet, continue trying to map it
        let address = address.0;
        let new_page = mm::alloc_page().expect("Unable to alloc page for fuzzvm::map_addr");


        let new_entry = EptEntry::from_addr(new_page.as_ptr() as u64, flags);


        if let Err(msg) = self.ept.map_page_raw(address, new_entry.entry, MapSize::Mapping4KiB, false)
        {
            panic!("[{}] {}", self.core_id, msg);
        }

        KernelPhysical(new_page.as_mut_ptr() as u64)
    }

    /// Identity map kernel physical memory in guest. Useful for mapping MMIO
    pub fn kernel_identity_map(&mut self, address: KernelPhysical) {
        let new_entry = EptEntry::from_addr(
            address.0,
            EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE,
        );

        if let Err(msg) = self.ept.map_page_raw(address.0, new_entry.entry, MapSize::Mapping4KiB, false)
        {
            panic!("[{}] {}", self.core_id, msg);
        }
    }

    /// For any MMIO page, we always map to a single blank page that does nothing
    pub fn mmio_map_blank_page(&mut self, address: GuestPhysical) {
        let new_entry = EptEntry::from_addr(
            self.mmio_addr, 
            EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE
        );

        if let Err(msg) = self.ept.map_page_raw(address.0, new_entry.entry, MapSize::Mapping4KiB, false)
        {
            panic!("[{}] {}", self.core_id, msg);
        }

    }

    /// Given a physical address and bytes to fill that address, map the address into the ept
    /// and then fill that page with the provided bytes
    pub fn map_bytes_phys(&mut self, address: GuestPhysical, bytes: &[u8], from: &'static str) {
        assert!(bytes.len() <= 4096);

        let paddr = match self.translate(address) {
            None => {
                let res = self.map_addr(address, EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE).0;
                res
            },
            Some(addr) => {
                let res = addr.0;
                panic!("[{}][{}] Already mapped? {:#x} -> {:#x}?? Resetting VM\n", self.core_id,
                    from, address.0, res);
            },
        };

        // Copy the bytes into the newly mapped address
        memcpy_slice(paddr as *mut u8, bytes);
    }

    /// Given a physical address and bytes to fill that address, map the address into the ept
    /// and then fill that page with the provided bytes
    pub fn map_page_phys(&mut self, address: GuestPhysical) {
        assert!(address.0 & 0xfff == 0);

        // let mut original_pages_write = ORIGINAL_PAGES.write();
        let lock_time_start = time::rdtsc();

        let mut original_pages_write = loop {
            match ORIGINAL_PAGES.try_write() {
                Some(lock) => break lock,
                None => { }
            }
        };

        stats::DEBUG_TIME_ORIGINAL_PAGES_LOCK.fetch_add(time::rdtsc() - lock_time_start, Ordering::Acquire);

        // Query to see if we have gotten this page already from TFTP
        // If so, use that page, otherwise, download via TFTP and save it
        match original_pages_write.get(&address) {
            None => {
                assert!(!original_pages_write.contains_key(&address));

                let code_file = format!("SNAPSHOT_page_{:016x}", address.0);
                let code_page = net::get_file(&code_file);

                let new_code_page = mm::alloc_page().expect("Failed to allocate new bytes page");

                unsafe {
                    let bytes = &mut *(new_code_page as *mut [u8; 4096]);
                    bytes.copy_from_slice(&code_page);
                }

                // Map and copy the bytes into the VM itself
                self.map_bytes_phys(address, &code_page, "Orig");

                // Insert the page into the local cache map of original page data
                let _res = original_pages_write.insert(address, *new_code_page);
            }
            Some(original_bytes) => {
                // print!("Found cached page.. {:#x} -> {:#x}\n", address.0, original_bytes_addr.0);
                self.map_bytes_phys(address, original_bytes, "Cache");
            },
        }
    }

    /// Given a virtual address, retrieve that pages bytes from TFTP, map the address into the 
    /// ept, and then fill that page with the page bytes
    pub fn map_page(&mut self, address: GuestVirtual) {
        // assert!(address.0 != 0, "Trying to map page 0");
        let address = GuestVirtual(address.0 & 0xffff_ffff_f000);

        let mut curr_guest_virt_to_guest_phys = self.guest_virt_to_guest_phys_maps
            .get_mut(&self.cr3)
            .expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps");


        let translated = match curr_guest_virt_to_guest_phys.get(&address) {
                Some(addr) => {
                    // Already have this page in local cache, use those bytes instead
                    *addr
                }
                None => {
                    // Haven't seen this page before. 
                    // Ask the server for the physical page for the wanted virtual page and pull
                    // that page over TFTP

                    let code_file = format!("SNAPSHOT_translate_{:016x}_{:016x}", 
                        self.cr3, address.0);
                    let address_bytes = net::get_file(&code_file);
                    assert!(address_bytes.len() == 8);

                    // Physical address for the requested virtual address
                    let mut addr = u64::from_le_bytes(
                        unsafe { *(address_bytes.as_slice().as_ptr() as *const [u8; 8])} 
                    );

                    if addr == 0 {
                        // In the situation where a new allocation occurred in the guest, but was
                        // not originally present in the snapshot, we need to get the translation
                        // of the new allocation into the EPT

                        // We need a &mut self at this location, so we explicitly drop the previous
                        // &self in order to call map_page (which needs &mut self)
                        ::core::mem::drop(curr_guest_virt_to_guest_phys);

                        // print!("Not found in snapshot.. let's see if it is newly allocated\n");
                        let mut cur = self.cr3;
                        let vaddr = address.0;
                        let offsets: [u64; 4] = [
                            ((vaddr >> 39) & 0x1ff), /* 512 GiB */
                            ((vaddr >> 30) & 0x1ff), /*   1 GiB */
                            ((vaddr >> 21) & 0x1ff), /*   2 MiB */
                            ((vaddr >> 12) & 0x1ff), /*   4 KiB */
                        ];

                        let mut error_string = String::new();
                        for (_depth, cur_offset) in offsets.iter().enumerate() {
                            let curr_addr = cur + cur_offset * 8;
                            let res = self.read_u64_phys(GuestPhysical(curr_addr));
                            error_string += &format!("{:#x}_", res);
                            if res ==  0  {
                                print!("Couldn't find {:#x} in page table", vaddr);
                                self.should_resume = false;
                                match &self.input_file {
                                    Some(ref input_file) => {
                                        net::put_file(
                                            &format!("unknown_address_{}.bimx", error_string), 
                                            input_file
                                        );
                                    }
                                    None => { print!("[unknown_address] No input file given..\n") }
                                }

                                return;
                            }

                            let res = res & 0x000fffff_fffff000;
                            cur = res;
                        }

                        addr = cur;

                        // Reget the curr_guest_virt_to_guest_phys
                        curr_guest_virt_to_guest_phys = self.guest_virt_to_guest_phys_maps
                                .get_mut(&self.cr3)
                                .expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps");

                    }

                    let translated_addr =  GuestPhysical(addr);
                    curr_guest_virt_to_guest_phys.insert(address, translated_addr);
                    translated_addr
                }
        };

        if self.translate(translated).is_some() { 
            // Page is already mapped in the EPT
            //
            // It's possible to map a page by physical address by EPT violation
            // but if our local VirtToPhys map doesn't have the entry already,
            // we can call this function to add the entry. We don't want to remap
            // the map, so we ignore mapping the page
            return;
        }


        self.map_page_phys(translated);
    }

    /// Translate a guest physical to kernel physical address
    pub fn translate(
        &mut self,
        address: GuestPhysical,
    ) -> Option<KernelPhysical> {
        match self.ept.virt_to_phys(address) {
            Ok(addr) => { addr }
            Err(msg) => {
                panic!("[{}] {}", self.core_id, msg);
            }
        }
    }

    /// Write a slice of bytes to a given physical address in the guest VM
    pub fn write_bytes_phys(
        &mut self,
        vaddr: GuestPhysical,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        // Calculate the virtual addresses per byte in case the bytes
        // written span multiple pages which aren't necessarily contiguous
        // in memory
        for (byte_index, curr_byte) in bytes.iter().enumerate() {
            let curr_vaddr = vaddr.0 + byte_index as u64;
            let vaddr_page = curr_vaddr & 0xffff_ffff_ffff_f000;
            let offset = curr_vaddr & 0xfff;

            // let ept = self.epts.get_mut(&self.cr3).expect("Unknown cr3 for getting ept");

            // Dirty the page we wrote the byte to
            assert!(self.ept.virt_to_phys_dirty(vaddr, true).is_ok());

            if let Some(paddr_page) = self.translate(GuestPhysical(vaddr_page)) {
                let curr_addr = paddr_page.0 + offset as u64;
                unsafe {
                    *(curr_addr as *mut u8) = *curr_byte;
                }
            } else {
                return Err("Page not found to write bytes");
            }
        }

        Ok(())
    }

    /// Write a slice of bytes into a given virtual address in the guest VM
    pub fn write_bytes(&mut self, address: GuestVirtual, bytes: &[u8]) {
        // Get the different physical pages needed to fulfil this write request
        let addrs_to_write = split_on_page_boundaries(address.0, bytes.len() as u64);

        let mut bytes_offset = 0;
        for (guest_virt, write_size) in addrs_to_write { 
            let offset = guest_virt & 0xfff;
            let input_page = guest_virt & 0xffff_ffff_f000;

            let guest_virt_to_guest_phys = self.guest_virt_to_guest_phys_maps
                .get(&self.cr3)
                .expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps");

            // Convert the snapshot virtual address to the snapshot physical address
            let translated = match guest_virt_to_guest_phys.get(&GuestVirtual(input_page)) {
                Some(address) => address.0.clone(),
                None => {
                    // Our attempted write_bytes page is not currently mapped. 
                    // Attempt to map it.
                    //
                    // We need a &mut self at this location, so we explicitly drop the previous
                    // &self in order to call map_page (which needs &mut self)
                    ::core::mem::drop(guest_virt_to_guest_phys);

                    // Ensure our hack of setting should_resume on error will work
                    // assert!(self.should_resume);

                    self.map_page(GuestVirtual(input_page));

                    // TODO: FIX THIS HACKY METHOD OF IF WE CAN'T GET THE ADDRESS OF THE PAGE WE
                    // ARE LOOKING FOR
                    self.guest_virt_to_guest_phys_maps 
                        .get(&self.cr3)
                        .expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps")
                        .get(&GuestVirtual(input_page))
                        .expect("Unable to map address for read_bytes")
                        .0 // Get the GuestPhysical.0 field
                        .clone()
                }
            };

            let curr_bytes = &bytes[bytes_offset as usize..(bytes_offset + write_size) as usize];
            match self.write_bytes_phys(GuestPhysical(translated + offset), curr_bytes) {
                Err(msg) => {
                    panic!("[{}][{:#x}] {}\n", self.core_id, self.get_rip(), msg);
                }
                _ => {}
            }

            // Update the current bytes offset after writing the current slice
            bytes_offset += write_size;
        }
    }

    /// Read a slice of bytes to a given physical address in the guest VM
    pub fn read_bytes_phys(
        &mut self,
        vaddr: GuestPhysical,
        size: u64,
    ) -> Result<&[u8], &'static str> {
        let offset = vaddr.0 & 0xfff;
        let vaddr = vaddr.0 & 0xffff_ffff_ffff_f000;
        if let Some(paddr) = self.translate(GuestPhysical(vaddr)) {
            unsafe {
                Ok(core::slice::from_raw_parts(
                    (paddr.0 + offset) as *const u8,
                    size as usize,
                ))
            }
        } else {
            Err("Page not found to read bytes")
        }
    }


    /// Read a slice of bytes to a given virtual address in the guest VM
    pub fn read_bytes(&mut self, address: GuestVirtual, size: u64) -> Vec<u8> {
        // Get the different physical pages needed to fulfil this read request
        let addrs_to_read = split_on_page_boundaries(address.0, size);

        let mut result = Vec::new();

        for (guest_virt, read_size) in addrs_to_read { 
            let offset = guest_virt & 0xfff;
            let input_page = guest_virt & 0xffff_ffff_f000;
            let guest_virt_to_guest_phys = self.guest_virt_to_guest_phys_maps
                                            .get(&self.cr3)
                                            .expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps");

            let translated = match guest_virt_to_guest_phys.get(&GuestVirtual(input_page)) {
                Some(address) => address.0.clone(),
                None => {
                    // Our attempted read_bytes page is not currently mapped. 
                    // Attempt to map it.
                    //
                    // We need a &mut self at this location, so we explicitly drop the previous
                    // borrow of self in order to call map_page (which needs &mut self)
                    // print!("read_bytes addr not found.. mapping it in {:#x}\n", input_page);
                    ::core::mem::drop(guest_virt_to_guest_phys);

                    self.map_page(GuestVirtual(input_page));

                    // TODO: FIX THIS HACKY METHOD OF IF WE CAN'T GET THE ADDRESS OF THE PAGE WE
                    // ARE LOOKING FOR
                    if self.should_resume == false {
                        return Vec::new();
                    }

                    self.guest_virt_to_guest_phys_maps
                        .get(&self.cr3)
                        .expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps")
                        .get(&GuestVirtual(input_page))
                        .expect("Unable to map address for read_bytes")
                        .0 // Deref the GuestPhysical address 
                        .clone()
                }
            };

            let core_id = self.core_id;
            match self.read_bytes_phys(GuestPhysical(translated + offset), read_size) {
                Ok(bytes) => result.extend(bytes),
                Err(msg) => {
                    panic!("[{}] {}\n", core_id, msg);
                }
            }
        }

        result
    }

    /// Attempts to read a UTF8 string from the given GuestVirtual address.
    pub fn read_utf8_str(&mut self, address: GuestVirtual) -> Result<String, FromUtf8Error> {
        let mut res = Vec::new();
        let mut addr = address;
        loop {
            // Grab the next byte
            let next_byte = self.read_u8(addr);

            // If it's null, we've reached the end of the string, break
            if next_byte == 0 { 
                break; 
            }

            // Add the byte to the result
            res.push(next_byte);

            // Increment the string pointer
            addr.0 += 1;
        }

        String::from_utf8(res)
    }

    /// Attempts to read a UTF16 string from the given GuestVirtual address.
    pub fn read_utf16_str(&mut self, address: GuestVirtual) -> Result<String, FromUtf16Error> {
        let mut res = Vec::new();
        let mut addr = address;
        loop {
            // Grab the next byte
            let next_byte = self.read_u16(addr);

            // If it's null, we've reached the end of the string, break
            if next_byte == 0 { 
                break; 
            }

            // Add the byte to the result
            res.push(next_byte);

            // Increment the string pointer
            addr.0 += 1;
        }

        String::from_utf16(&res)
    }

    /// Read a u64 from GuestVirtual address
    pub fn read_u64(&mut self, address: GuestVirtual) -> u64 {
        u64::from_le_bytes(self.read_bytes(address, 8)
                               .as_slice()
                               .try_into()
                               .expect("Wrong length array from read_u64"))
    }

    /// Read a u32 from GuestVirtual address
    pub fn read_u32(&mut self, address: GuestVirtual) -> u32 {
        u32::from_le_bytes(self.read_bytes(address, 4)
                               .as_slice()
                               .try_into()
                               .expect("Wrong length array from read_u32"))
    }

    /// Read a u16 from GuestVirtual address
    pub fn read_u16(&mut self, address: GuestVirtual) -> u16 {
        u16::from_le_bytes(self.read_bytes(address, 2)
                               .as_slice()
                               .try_into()
                               .expect("Wrong length array from read_u16"))
    }

    /// Read a u8 from GuestVirtual address
    pub fn read_u8(&mut self, address: GuestVirtual) -> u8 {
        u8::from_le_bytes(self.read_bytes(address, 1)
                              .as_slice()
                              .try_into()
                              .expect("Wrong length array from read_u8"))
    }

    /// Read a u64 from GuestPhysical address
    pub fn read_u64_phys(&mut self, address: GuestPhysical) -> u64 {
        u64::from_le_bytes(self.read_bytes_phys(address, 8)
                              .expect("Failure reading bytes phys")
                              .try_into()
                              .expect("Wrong length array from read_u64"))
    }

    /// Read a u32 from GuestPhysical address
    pub fn read_u32_phys(&mut self, address: GuestPhysical) -> u32 {
        u32::from_le_bytes(self.read_bytes_phys(address, 4)
                              .expect("Failure reading bytes phys")
                              .try_into()
                              .expect("Wrong length array from read_u32"))
    }

    /// Read a u16 from GuestPhysical address
    pub fn read_u16_phys(&mut self, address: GuestPhysical) -> u16 {
        u16::from_le_bytes(self.read_bytes_phys(address, 2)
                              .expect("Failure reading bytes phys")
                              .try_into()
                              .expect("Wrong length array from read_u16"))
    }

    /// Read a u8 from GuestPhysical address
    pub fn read_u8_phys(&mut self, address: GuestPhysical) -> u8 {
        u8::from_le_bytes(self.read_bytes_phys(address, 1)
                              .expect("Failure reading bytes phys")
                              .try_into()
                              .expect("Wrong length array from read_u8"))
    }

    /// Print a hexdump at the given GuestPhysical address of the given size
    pub fn hexdump_phys(&mut self, address: GuestPhysical, size: u64) {
        print!("hexdump_phys: {:#x} len: {:#x}\n", address.0, size);
        let offset = address.0 & 0xfff;
        let address = address.0 & 0xffff_ffff_f000;

        match self.translate(GuestPhysical(address)) {
            Some(KernelPhysical(phys_addr)) => crate::tools::hexdump(phys_addr + offset, size),
            None => print!("[hexdump] address not found: {:#x}\n", address),
        }
    }

    /// Print a hexdump at the given GuestVirtual address of the given size
    pub fn hexdump(&mut self, address: GuestVirtual, size: u64) {
        let offset = address.0 & 0xfff;
        let address = GuestVirtual(address.0 & 0xffff_ffff_f000);
        let mut curr_guest_virt_to_guest_phys = self.guest_virt_to_guest_phys_maps
                .get_mut(&self.cr3).expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps");

        let translated = match curr_guest_virt_to_guest_phys.get(&address) {
                Some(addr) => *addr,
                None => {
                    let code_file = format!("SNAPSHOT_translate_{:016x}_{:016x}", self.cr3, address.0);
                    let address_bytes = net::get_file(&code_file);
                    assert!(address_bytes.len() == 8);

                    let mut addr = u64::from_le_bytes(unsafe { *(address_bytes.as_slice().as_ptr() 
                            as *const [u8; 8])} );

                    if addr == 0 {
                        // In the situation where a new allocation occurred in the guest, but was
                        // not originally present in the snapshot, we need to get the translation
                        // of the new allocation into the EPT

                        // We need a &mut self at this location, so we explicitly drop the previous
                        // &self in order to call map_page (which needs &mut self)
                        ::core::mem::drop(curr_guest_virt_to_guest_phys);

                        // print!("Not found in snapshot.. let's see if it is newly allocated\n");
                        let mut cur = self.cr3;
                        let vaddr = address.0;
                        let offsets: [u64; 4] = [
                            ((vaddr >> 39) & 0x1ff), /* 512 GiB */
                            ((vaddr >> 30) & 0x1ff), /*   1 GiB */
                            ((vaddr >> 21) & 0x1ff), /*   2 MiB */
                            ((vaddr >> 12) & 0x1ff), /*   4 KiB */
                        ];
                        for (_depth, cur_offset) in offsets.iter().enumerate() {
                            let curr_addr = cur + cur_offset * 8;
                            let res = self.read_u64_phys(GuestPhysical(curr_addr));
                            // print!("{:#x} -> {:#x}\n", curr_addr, res);
                            if res ==  0  {
                                panic!("Couldn't find {:#x} in page table", vaddr);
                            }
                            let res = res & 0x000fffff_fffff000;
                            // print!("{:#x} -> {:#x}\n", curr_addr, res);
                            cur = res;
                        }

                        // print!("{:#x} -> {:#x}\n", address.0, cur);
                        addr = cur;

                        // Reget the curr_guest_virt_to_guest_phys
                        curr_guest_virt_to_guest_phys = self.guest_virt_to_guest_phys_maps
                                .get_mut(&self.cr3)
                                .expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps");

                    }

                    let translated_addr =  GuestPhysical(addr);
                    curr_guest_virt_to_guest_phys.insert(address, translated_addr);
                    translated_addr
                }
        };

        self.hexdump_phys(GuestPhysical(translated.0 + offset), size);
    }

    /// Reset the VM to a clean state for the next fuzz run
    pub fn reset(&mut self) {
        // Start timer for resetting
        let timer_start_nonpage_reset = time::rdtsc();

        // Closure used to reset each dirty page
        let _print_page = |guest_phys: GuestPhysical, paddr: KernelPhysical, _core_id: u32| {
            print!("{:#x} -> {:#x}\n", guest_phys.0, paddr.0);
        };

        // Closure used to reset each dirty page
        let reset_page = |guest_phys: GuestPhysical, paddr: KernelPhysical, _core_id: u32| {
            // Don't try to remap MMIO pages on reset
            if guest_phys.0 == 0xfee00000 || guest_phys.0 == 0xfed00000 {
                return;
            }

            let lock_time_start = time::rdtsc();
            let original_pages_read = loop {
                match ORIGINAL_PAGES.try_read() {
                    Some(lock) => break lock,
                    None => { 
                        // print!("[{}] Lock stuck in fuzzvm.rs 1836\n", _core_id) 
                    }
                }
            };
            stats::DEBUG_TIME_ORIGINAL_PAGES_LOCK.fetch_add(time::rdtsc() - lock_time_start, Ordering::Acquire);

            if let Some(original_bytes) = original_pages_read.get(&guest_phys) {
                memcpy(paddr.0 as *mut u8, original_bytes.as_ptr(), 0x1000);
            }
        };

        // For each dirty page found in the EPT, reset it back to the original bytes
        let vmx_ept_cap = unsafe { Msr::new(IA32_VMX_EPT_VPID_CAP).read() };
        let dirty_pages_available = if (vmx_ept_cap >> 21) & 1 == 0 { false } else { true };
        assert!(dirty_pages_available);

        // Start timer for resetting
        let timer_start_reset = time::rdtsc();

        let num_pages = unsafe {
            self.ept.for_each_page(true, reset_page, self.core_id) .expect("Error ept.for_each_page")
            // self.ept.reset_each_page(true, self.core_id) .expect("Error ept.for_each_page")
        };

        // Mark time for VM reset in stats
        let page_reset_time = time::rdtsc() - timer_start_reset;
        stats::DEBUG_TIME_RESET.fetch_add(page_reset_time, Ordering::Acquire);

        stats::PAGES_PER_RESET.fetch_add(num_pages, Ordering::Acquire);

        // Invalidate EPT
        // self.invept_global();

        // Invalidate linear mappings for this vpid
        // self.invvpid_all();
        // self.invvpid_keep_global();
        self.invvpid_self();

        // Reset register state to the original register state
        self.regs = self.orig_regs.clone();

        // Reset the original CR3 value
        self.cr3 = self.vbcpu.cr3;

        // BE SURE TO RESET KERNEL GS BASE!
        self.msrs.insert(IA32_KERNEL_GS_BASE, self.vbcpu.msr_kernel_gs_base);

        // Default to no new coverage
        self.new_coverage = false;

        // Reset the executed instrs
        self.executed_instrs = 0;

        // Reset VMCS
        self.init();

        // Reset trace
        self.trace.clear();
        self.verbose_trace.clear();

        // Clear the current coverage
        self.coverage.clear();

        // Clear all files used in this fuzz case
        self.files.clear();

        // Clear the mutations from the previous run
        self.mutations = None;
        self.input_file = None;


        let _virtual_apic_addr = mm::alloc_page().expect("Failed to allocate virtual apic page")
            .as_ptr() as u64;
        let _apic_access_addr = mm::alloc_page().expect("Failed to allocate apic access page")
            .as_ptr() as u64;

        stats::DEBUG_TIME_NONPAGE_RESET.fetch_add(time::rdtsc() - timer_start_nonpage_reset - page_reset_time,  
            Ordering::Acquire);
    }

    /// Fuzz the current VM based on the given fuzzer
    pub fn fuzz(&mut self) {
        // Leverage Option's .take() function to "move" the function pointer
        // out to use it and then set it back in the Box itself. This helps
        // the borrow checker.
        let fuzz_fn = self.fuzz_fn.take().expect("Unable to take fuzz_fn");
        (fuzz_fn)(self);
        self.fuzz_fn = Some(fuzz_fn);
    }

    /// Return the current input file from the VM
    pub fn get_input_file(&mut self) -> Option<Vec<u8>> {
        if self.input_file_fn.is_none() {
            return None;
        }

        // Leverage Option's .take() function to "move" the function pointer
        // out to use it and then set it back in the Box itself. This helps
        // the borrow checker.
        let input_file_fn = self.input_file_fn.take().expect("Unable to take input_file_fn");
        let res = (input_file_fn)(self);
        self.input_file_fn = Some(input_file_fn);
        Some(res)
    }

    /// Update current VM with a new CR3 and EPT
    pub fn new_cr3(&mut self, cr3: u64) {
        self.cr3 = cr3;

        self.cr3s.insert(cr3);

        // Update Guest CR3 with new CR3 
        vmwrite(VMCS_GUEST_CR3, self.cr3);

        // Create a new guest vaddr to paddr map for this cr3
        if !self
            .guest_virt_to_guest_phys_maps
            .contains_key(&self.cr3) {
                self.guest_virt_to_guest_phys_maps.insert(self.cr3, HashMap::new());
        }
    }

    /// Increment RIP by VMEXIT instruction length and rewrite RIP value back to the VM
    pub fn update_rip(&mut self) {
        // Increment rip by VMEXIT instr length
        let instruction_length = vmread(VMCS_VMEXIT_INSTR_LENGTH);
        self.set_rip(self.get_rip() + instruction_length);

        // Inject #DB if TF is set in RFLAGS
        if RFlags::from_bits_truncate(self.regs.rflags).contains(RFlags::TRAP) {
            self.inject_fault(ExceptionVector::Debug, InterruptionType::Hardware, None);
            panic!("[{}] Updating RIP while RFLAGS is set", self.core_id);
        }

        // Rewrite newly calculated RIP back to the VM
        vmwrite(VMCS_GUEST_RIP, self.get_rip());
    }

    /// INVVPID with all context
    pub fn invvpid_all(&self) {
        let desc = InvVpidDescriptor::default();
        invvpid(InvVpidType::AllContextxInvalidation, desc).expect("INVVPID all fail");
    }

    /// INVVPID with single context while keeping global translations
    pub fn invvpid_self(&self) {
        let mut desc = InvVpidDescriptor::default();
        desc.vpid = (self.core_id) as u16;
        invvpid(InvVpidType::SingleContextInvalidation, desc).expect("INVVPID self fail");
    }

    /// INVVPID with single context while keeping global translations
    pub fn invvpid_keep_global(&self) {
        let mut desc = InvVpidDescriptor::default();
        desc.vpid = (self.core_id) as u16;
        invvpid(InvVpidType::SingleContextInvalidationRetainingGlobal, desc).expect("INVVPID global fail");
    }

    /// INVEPT with all contexts
    pub fn invept_global(&self) {
        let desc = InvEptDescriptor::default();
        invept(InvEptType::GlobalInvalidation, desc).expect("Error in invept");
    }

    pub fn inject_fault_1f(&mut self) {
        // print!("Inject 1f software interrupt\n");
        self.inject_fault(ExceptionVector::Fault1f, InterruptionType::Software, None);
    }

    pub fn inject_fault_2f(&self) {
        // print!("Inject 2f software fault!\n");
        self.inject_fault(ExceptionVector::Fault2f, InterruptionType::Software, None);
    }

    /// Inject the given exception back into the guest
    pub fn inject_fault(&self, vector: ExceptionVector, interruption_type: InterruptionType, error_code: Option<u64>) {
        let new_fault = InterruptionInfo { 
            vector, 
            interruption_type, 
            error_code_valid: error_code.is_some(), 
            valid: true 
        };

        vmwrite(VMCS_VMENTRY_INTERRUPTION_INFO_FIELD, new_fault.into());

        if error_code.is_some() {
            vmwrite(VMCS_VMENTRY_EXCEPTION_ERRCODE, error_code.expect("Unable to inject fault"));
        }
    }

    /// Inject a #GP fault into the guest
    pub fn inject_general_protection_fault(&self) {
        let error_code = vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE);
        self.inject_fault(ExceptionVector::GeneralProtection, InterruptionType::Hardware, 
            Some(error_code));
    }

    /// Inject a #PF fault into the guest
    pub fn inject_page_fault(&mut self) {
        // Set the faulting address to CR2 (as per the specification)
        let fault_address = vmread(VMCS_EXIT_QUALIFICATION);
        self.regs.cr2 = fault_address;

        let error_code = vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE);
        if self.is_guest_64bit() {
            self.inject_fault(ExceptionVector::PageFault, InterruptionType::Hardware, 
                Some(error_code));

            if false {
                print!(
                    "RIP: {:#x} #PF Fault: {:#x} Code: {:#x}\n",
                    self.get_rip(),
                    fault_address,
                    error_code
                );
            }
        } else {
            print!(
                "[32bit] Mapping.. RIP: {:#x} #PF Fault: {:#x} Code: {:#x}\n",
                self.get_rip(),
                fault_address,
                error_code
            );
            
            // Map that physical page to the VM
            self.map_page(GuestVirtual(fault_address));

            // Invalidate previous EPT entries
            self.invept_global();
        }
    }

    /// Write all the MSRs that aren't contained in the VMCS itself
    ///
    /// Current MSRs loaded this way:
    /// ```
    /// IA32_STAR
    /// IA32_LSTAR
    /// IA32_CSTAR
    /// IA32_SFMASK
    /// IA32_KERNEL_GS_BASE
    /// ```
    pub fn vmwrite_msrs(&self) {
        if self.msrs.len() == 0 {
            vmwrite(VMCS_VMENTRY_MSR_LOAD_ADDR, 0);
            vmwrite(VMCS_VMENTRY_MSR_LOAD_ADDR_HIGH, 0);
            vmwrite(VMCS_VMENTRY_MSR_LOAD_COUNT, 0);
            return;
        }

        struct EntryMsr {
            msr: u64,
            value: u64,
        }

        for (i, (msr, value)) in self.msrs.iter().enumerate() {
            let curr_addr = self.msr_load_page + (i * 16) as u64;
            let mut msr_load = curr_addr as *mut EntryMsr;

            unsafe {
                (*msr_load).msr = *msr;
                (*msr_load).value = *value;
            }
        }

        vmwrite(VMCS_VMENTRY_MSR_LOAD_ADDR, self.msr_load_page & 0xffff_ffff);
        vmwrite(VMCS_VMENTRY_MSR_LOAD_ADDR_HIGH, self.msr_load_page >> 32);
        vmwrite(VMCS_VMENTRY_MSR_LOAD_COUNT, self.msrs.len() as u64);
    }

    /// Sets the RIP of the guest as writes the new value with vmwrite We don't ever want to
    /// directly change the rip value in VMREGs because that value isn't always written back on
    /// vmlaunch/vmresume, so this function acts as the only gateway to change the GUEST RIP and
    /// ensure it is written into the VMCS.
    pub fn set_rip(&mut self, new_rip: u64) {
        self.regs.set_rip(new_rip);

        // Rewrite newly calculated RIP back to the VM
        vmwrite(VMCS_GUEST_RIP, self.regs.get_rip());
    }

    /// Sets the RIP of the guest as writes the new value with vmwrite We don't ever want to
    /// directly change the rip value in VMREGs because that value isn't always written back on
    /// vmlaunch/vmresume
    pub fn get_rip(&self) -> u64{
        self.regs.get_rip()
    }

    /// Given a set of permanent breakpoints from the fuzzer, patch the original pages to always
    /// contain breakpoints so that we don't have to reset the breakpoints each fuzz run.
    pub fn set_exit_breakpoints(&mut self, fuzzer: &impl Fuzzer) {
        for bp in fuzzer.exit_breakpoints() {
            match bp {
                Breakpoint::Virtual(virt_addr) => {
                    self.insert_permanent_breakpoint(virt_addr);
                }
                Breakpoint::Physical(_addr) => {
                    panic!("[{}] Physical memory breakpoints not added yet", 
                           self.core_id)
                }
            }
        }
    }

    pub fn apply_patches(&mut self, fuzzer: &impl Fuzzer) {
        for (address, bytes) in fuzzer.patches() {
            self.insert_permanent_patch(address, &bytes);
        }
    }

    /// Permanently insert a breakpoint into the fuzzvm. 
    ///
    /// If the page is not currently mapped, map that page. Regardless, adds the breakpoint into
    /// cache maps and the currently mapped page.
    pub fn insert_permanent_breakpoint(&mut self, addr: GuestVirtual) {
        self.insert_permanent_patch(addr, &[0xcc]);
    }

    pub fn insert_permanent_patch(&mut self, address: GuestVirtual, bytes: &[u8]) {
        let address = address.0;
        for (byte, addr) in bytes.iter().zip(address..address+bytes.len() as u64) {
            // print!("Inserting Perma Byte {:#x} at {:#x}\n", byte, addr);
            let offset = addr & 0xfff;
            let input_page = addr & 0xffff_ffff_f000;

            // Attempt to map the exit breakpoint page into the VM
            self.map_page(GuestVirtual(input_page));

            // Get the current translation (GuestVirtual->GuestPhysical) table
            let guest_virt_to_guest_phys = self.guest_virt_to_guest_phys_maps
                .get(&self.cr3)
                .expect("Unknown cr3 for getting guest_virt_to_guest_phys_maps");

            // Convert the snapshot virtual address to the snapshot physical address
            let translated = guest_virt_to_guest_phys
                .get(&GuestVirtual(input_page))
                .expect(format!("[{}][insert_permanent_breakpoint] BP addr not mapped: {:#x}",
                        self.core_id, input_page).as_str());

            // Acquire ORIGINAL_PAGES lock
            // let mut original_pages_write = ORIGINAL_PAGES.write();
            let lock_time_start = time::rdtsc();
            let mut original_pages_write = loop {
                match ORIGINAL_PAGES.try_write() {
                    Some(lock) => break lock,
                    None => { print!("Lock suck in main.rs:2178\n"); }
                }
            };
            stats::DEBUG_TIME_ORIGINAL_PAGES_LOCK.fetch_add(time::rdtsc() - lock_time_start, Ordering::Acquire);

            // Patch the page in the ORIGINAL_PAGES database
            match original_pages_write.get_mut(&translated) {
                None => { 
                    panic!("[{}][insert_permanent_breakpoint] BP page not in original pages", 
                        self.core_id) 
                }
                Some(original_bytes) => {
                    // Write the breakpoint in the ORIGINAL_PAGES
                    if let Some(curr_byte) = original_bytes.get_mut(offset as usize) {
                        // *byte = 0xcc;
                        *curr_byte = *byte;
                    } else {
                        panic!("Unable to get offset {} in original bytes\n", offset);
                    }
                }
            }

            // Get the physiscal address of the translated page in the VM
            let paddr = self.translate(*translated)
                .expect("Huh? GuestPhysical not found in translate\n");

            // Write the breakpoint in the currently mapped page
            // unsafe { *((paddr.0 + offset) as *mut u8) = 0xcc; }
            unsafe { *((paddr.0 + offset) as *mut u8) = *byte; }
        }
    }

    /// Given a set of hook breakpoints, replace the hook address with a 0xcc and call a callback
    /// when that breakpoint is hit.
    pub fn set_hooks(&mut self, fuzzer: &impl Fuzzer) {
        for (bp, callback) in fuzzer.hooks() {
            match bp {
                Breakpoint::Virtual(virt_addr) => {
                    self.insert_permanent_breakpoint(virt_addr);
                    self.hooks.insert(virt_addr, callback);
                }
                Breakpoint::Physical(_addr) => {
                    panic!("[{}] Physical memory breakpoints not supported", 
                           self.core_id)
                }
            }
        }
    }
    
    /// Return a random u8
    pub fn rand_u8(&mut self) -> u8 {
        self.rng.next() as u8
    }

    /// Return a random u16
    pub fn rand_u16(&mut self) -> u16 {
        self.rng.next() as u16
    }

    /// Return a random u32
    pub fn rand_u32(&mut self) -> u32 {
        self.rng.next() as u32
    }

    /// Return a random u64
    pub fn rand_u64(&mut self) -> u64 {
        self.rng.next() 
    }

    /// Given the wanted number of times for the preemption timer to fire per second, calculate and
    /// set the correct Preemption Timer Value based on the clock rate.
    pub fn set_preemption_timer_per_second(&mut self, wanted_timer_per_sec: u64) {
        if wanted_timer_per_sec > 0 {
            // See: A.6 Miscellaneous Data
            // Bits 4:0 report a value X that specifies the relationship between the 
            // rate of the VMX-preemption timer and that of the timestamp counter (TSC). 
            // Specifically, the VMX-preemption timer (if it is active) counts down by 
            // 1 every time bit X in the TSC changes due to a TSC increment
            let vmx_misc = unsafe { Msr::new(IA32_VMX_MISC).read() };
            let timer_rate = 2_u64.pow(((vmx_misc & 0xf)).try_into().unwrap());

            // Calculate the number of preemption timer ticks to achieve the wanted
            // number of fires per second (passed in argument)
            // let timer_value = (1.0 / wanted_timer_per_sec as f64) 
            // let timer_value = time::RDTSC_RATE.load(Ordering::SeqCst) as f64 * 1_000_000 as f64
            let cycles_per_second = time::RDTSC_RATE.load(Ordering::SeqCst) as f64 * 1_000_000 as f64;
            let preemption_timer_per_second = cycles_per_second / timer_rate as f64;
            let timer_value = preemption_timer_per_second / wanted_timer_per_sec as f64;
            let timer_value = timer_value as u64;

            // Save the Preempttion timer on VmExit
            let exit_or = ExitCtls::read_raw() & 0xffff_ffff;
            let exit_and = ExitCtls::read_raw() >> 32;
            let mut exit_ctls = ExitCtlsFlags::empty();
            exit_ctls.insert(ExitCtlsFlags::HOST_ADDRESS_SPACE_SIZE);
            exit_ctls.insert(ExitCtlsFlags::SAVE_VMX_PREEMPTION_TIMER_VALUE);

            // Write the VmExit Ctls
            vmwrite(
                VMCS_VMEXIT_CTL,
                (exit_ctls.bits() as u64 | exit_or) & exit_and,
            );

            // Activate the Preeemption timer itself
            let pin_ctrls_or = PinCtls::read_raw() & 0xffff_ffff;
            let pin_ctrls_and = PinCtls::read_raw() >> 32;
            let mut pin_ctls = PinCtlsFlags::empty();
            pin_ctls.insert(PinCtlsFlags::ACTIVE_VMX_PREEMPTION_TIMER);
            pin_ctls.insert(PinCtlsFlags::EXTERNAL_INT_EXIT);

            // Write the Pin Ctls
            vmwrite(VMCS_PIN_BASED_VMEXEC_CTL, 
                (pin_ctls.bits() as u64 | pin_ctrls_or) & pin_ctrls_and);

            // Write the timer value to the VM
            vmwrite(VMCS_GUEST_PREEMPTION_TIMER_VALUE, timer_value);

            // print!("Enabling Preemption Timer: {}\n", timer_value);
            self.timer = Some(timer_value);
        } else {
            // If we are disabling the timer, we also need to disable the VMCS flags
            // to disable the timer itself in the VM.
            
            // Disable save the Preempttion timer on VmExit
            let exit_or = ExitCtls::read_raw() & 0xffff_ffff;
            let exit_and = ExitCtls::read_raw() >> 32;
            let mut exit_ctls = ExitCtlsFlags::empty();
            exit_ctls.insert(ExitCtlsFlags::HOST_ADDRESS_SPACE_SIZE);

            vmwrite(
                VMCS_VMEXIT_CTL,
                (exit_ctls.bits() as u64 | exit_or) & exit_and,
            );

            // De-Activate the Preeemption timer itself
            let pin_ctrls_or = PinCtls::read_raw() & 0xffff_ffff;
            let pin_ctrls_and = PinCtls::read_raw() >> 32;
            let mut pin_ctls = PinCtlsFlags::empty();
            pin_ctls.insert(PinCtlsFlags::EXTERNAL_INT_EXIT);

            // Write the Pin Ctls
            vmwrite(VMCS_PIN_BASED_VMEXEC_CTL, 
                (pin_ctls.bits() as u64 | pin_ctrls_or) & pin_ctrls_and);

            // Write the timer value to the VM
            vmwrite(VMCS_GUEST_PREEMPTION_TIMER_VALUE, 0);

            // Set that no timer is currently being used
            self.timer = None;
        }
    }

    /// Disable the preemption timer by setting the correct VMCS fields and setting the Preemption
    /// timer count to 0
    pub fn disable_preemption_timer(&mut self) {
        self.set_preemption_timer_per_second(0);
    }

    /// Returns the Long Mode Enabled bit from the IA32_EFER MSR
    pub fn is_guest_64bit(&self) -> bool {
        self.vbcpu.msr_efer >> 8 & 1 == 1
    }

    /// Put the current verbose trace with the given filename over to the TFTP server
    pub fn put_verbose_trace(&self, filename: &str) {
        fn as_u8_slice<T: Sized>(data: &T) -> &[u8] {
            unsafe {
                ::core::slice::from_raw_parts((data as *const T) as *const u8, 
                    ::core::mem::size_of::<T>())
            }
        }

        let mut data: Vec<u8> = Vec::new();
        let mut file_index = 0;
        let mut curr_filename = format!("{}-{}", filename, file_index);

        let chunk_size = 0xffff_ffff;

        for (index, i) in self.verbose_trace.iter().enumerate() {
            for ch in as_u8_slice(&*i) {
                data.push(*ch);
            }
            if index > 0 && index % chunk_size == 0 {
                net::put_file(&curr_filename, &data);
                data.clear();
                file_index += 1;
                curr_filename = format!("{}-{}", filename, file_index);
            }
        }

        net::put_file(&curr_filename, &data);
    }

    /// Send the current trace over TFTP with the given filename
    pub fn put_trace(&self, filename: &str) {
        let mut data: Vec<u8> = Vec::new();
        let mut file_index = 0;
        let mut curr_filename = format!("{}-{}", filename, file_index);

        let start_index = self.trace.len().saturating_sub(1_000_000);

        let chunk_size = 0xffff_ffff;
        for (index, addr) in self.trace[start_index..].iter().enumerate() {
            data.extend(&addr.to_le_bytes());
            if index > 0 && index % chunk_size == 0 {
                net::put_file(&curr_filename, &data);
                data.clear();
                file_index += 1;
                curr_filename = format!("{}-{}", filename, file_index);
            }
        }

        net::put_file(&curr_filename, &data);
    }

    /// Enable single step by setting the Monitor Trap Flag
    pub fn enable_single_step(&mut self) {
        // print!("Enable single step\n");
        self.single_step = true;
        self.set_procbased_flags();
    }

    /// Disable single step by removing the Monitor Trap Flag
    pub fn disable_single_step(&mut self) {
        // print!("Disable single step\n");
        self.single_step = false;
        self.set_procbased_flags();
    }

    /// Returns whether or not the current fuzzer wants to log the current coverage location
    pub fn should_log_coverage(&self) -> bool {
        let curr_rip = self.get_rip();
        match &self.coverage_type {
            CoverageType::All => true,
            CoverageType::User => curr_rip >> 63 == 0,
            CoverageType::Kernel => curr_rip >> 63 == 1,
            CoverageType::Ranges(ranges) => {
                let mut result = false;
                for range in ranges {
                    if range.contains(&curr_rip) {
                        result = true; 
                        break;
                    }
                }
                result
            },
            CoverageType::None => false
        }
    }

    /// Fuzzer callback called before fuzz
    pub fn pre_fuzz_callback(&mut self) {
        // Leverage Option's .take() function to "move" the function pointer
        // out to use it and then set it back in the Box itself. This helps
        // the borrow checker.
        if let Some(pre_fuzz_fn) = self.pre_fuzz_fn.take() {
            (pre_fuzz_fn)(self);
            self.pre_fuzz_fn = Some(pre_fuzz_fn);
        }
    }

    /// Fuzzer callback called after fuzz
    pub fn post_fuzz_callback(&mut self) {
        // Leverage Option's .take() function to "move" the function pointer
        // out to use it and then set it back in the Box itself. This helps
        // the borrow checker.
        if let Some(post_fuzz_fn) = self.post_fuzz_fn.take() {
            (post_fuzz_fn)(self);
            self.post_fuzz_fn = Some(post_fuzz_fn);
        }
    }

    /// Fuzzer callback called during the stats display time slot
    pub fn stats_callback(&mut self) {
        // Leverage Option's .take() function to "move" the function pointer
        // out to use it and then set it back in the Box itself. This helps
        // the borrow checker.
        if let Some(stats_fn) = self.stats_fn.take() {
            (stats_fn)(self);
            self.stats_fn = Some(stats_fn);
        }
    }

    /// Fuzzer callback called during single stepping
    pub fn single_step_callback(&mut self) {
        // Leverage Option's .take() function to "move" the function pointer
        // out to use it and then set it back in the Box itself. This helps
        // the borrow checker.
        if let Some(single_step_fn) = self.single_step_fn.take() {
            (single_step_fn)(self);
            self.single_step_fn = Some(single_step_fn);
        }
    }
}

/// Internal function to split a virtual address and size into the corresponding physical pages and
/// their size for reading and writing
///
/// Virtual addresses that reach beyond one page will not necessarily be contiguous physical pages
/// in the kernel. For this reason, we need to split reads/writes based on page boundaries, so we
/// precalculate the addresses needed to read/write from and the sizes to read/write from those
/// addresses. An example is below
///
/// Virtual Address: 0x233fced8550 Read size: 0x33de
///     Addr           Sizes
///     0x233fced8550  0xab0
///     0x233fced9000  0x1000
///     0x233fceda000  0x1000
///     0x233fcedb000  0x92e
///
/// After precalculating these addresses, we translate the virtual address for the physical
/// address, and then read/write the calculated size, so that from the API perspective it feels
/// like reading/writing from/to contiguous memory.
fn split_on_page_boundaries(address: u64, size: u64) -> Vec<(u64, u64)> {
    let mut addrs = Vec::new();
    let mut curr_size = size;
    let mut curr_addr = address;
    let timeout = time::future(5 * 1000 * 1000);
    loop {
        // Determine the offset from the current address to the next page boundary
        if curr_addr & 0xfff != 0 {
            let size_to_next_page = ((curr_addr + 0xfff) & !0xfff) - curr_addr;
            // print!("size to next page: {:#x} curr_size: {:#x}\n", size_to_next_page, curr_size);
            if size_to_next_page > curr_size {
                addrs.push((curr_addr, size));
                break;
            } else {
                // Size is beyond one page, add the offset to the page and continue
                addrs.push((curr_addr, size_to_next_page));
                curr_addr += size_to_next_page;
                curr_size -= size_to_next_page;
            }
        } else {
            //  Current address is at a page boundary
            if curr_size >= 0x1000 {
                addrs.push((curr_addr, 0x1000));
                curr_addr += 0x1000;
                curr_size -= 0x1000;
            } else {
                // Othersize we are at the end of the read
                addrs.push((curr_addr, curr_size));
                break;
            }
        }

        if timeout < time::rdtsc() {
            panic!("TIMEOUT ON SPLIT ON PAGE BOUNDARIES");
        }
    }

    addrs
}

impl core::fmt::Debug for VmxOn {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let s = format!("VmxOn(revision_id: {:#x})\n", self.revision_id);
        f.write_str(&s)
            .expect("Unable to write string for VmxOn Debug");
        Ok(())
    }
}

/* Store KERNEL GS BASE on VMExit in order to keep our internal state correct */
#[derive(Debug, Copy, Clone)]
#[repr(packed)]
struct VmExitStoreEntryMsr {
    msr: u64,
    value: u64,
}

/// Calculate how many clock cycles the instructions just before vmlaunch/vmresume take to more
/// accurately measure the time the VM takes to execute. 
fn vmlaunch_pre_offset(regs: VmRegs) -> u64 {
    let regs_addr = &(regs) as *const VmRegs as u64;
    let mut result = Vec::new();
    for _ in 0..10 {
        let time_start = time::rdtsc();

        unsafe {
            // let mut result: u64;

           llvm_asm!(r#"
                # Save all registers since everything is clobbered
                push rbx
                push rcx
                push rdx
                push rbp
                push r8
                push r9
                push r10
                push r11
                push r12
                push r13
                push r14
                push r15
                pushf

                # Save the address of VmRegs for later use
                push rdi 

                # Set Guest RFLAGS from VmRegs
                mov rbx, [rdi + 8*18]
                or rbx, 2 # Must have 2 set in rflags
                mov rax, 0x6820
                vmwrite rax, rbx 

                # Set HOST RSP for when the guest VM VMEXITS
                mov rax, 0x6c14
                vmwrite rax, rsp

                # Set HOST RIP for when the guest VM VMEXITS
                mov rax, 0x6c16
                lea rbx, [rip + 1f]
                vmwrite rax, rbx

                #  Set CR2 for the guest
                mov rax, [rdi + 8*4]
                mov cr2, rax

                # Setup xcr0
                xor ecx, ecx
                xgetbv     # Load XCR0
                or eax, 7  # Enable AVX, SSE, X87
                # or eax, 0x1f  # Enable AVX, SSE, X87, BNDREG, BNDCSR
                # or eax, 0xff  # Enable AVX, SSE, X87, BNDREG, BNDCSR, AVX512
                xsetbv     # Save XCR0

                # Save the host xstate and restore the guest 
                mov rdx, 0xffffffffffffffff
                mov rax, 0xffffffffffffffff
                mov rbx, [rdi + 8*22] # host xstate
                xsave [rbx]
                mov rbx, [rdi + 8*21] # guest xstate
                xrstor [rbx]

                # Restore general purpose regs
                mov r8, [rdi + 8*8]
                mov r9, [rdi + 8*9]
                mov r10, [rdi + 8*10]
                mov r11, [rdi + 8*11]
                mov r12, [rdi + 8*12]
                mov r13, [rdi + 8*13]
                mov r14, [rdi + 8*14]
                mov r15, [rdi + 8*15]
                mov rcx, [rdi + 8*1]
                mov rbx, [rdi + 8*3]
                mov rbp, [rdi + 8*5]
                mov rsi, [rdi + 8*6]

                # Restore cr8
                # mov rax, [rdi + 8*29]
                # mov cr8, rax
                # xor rax, rax

                # Save the current timecounter
                rdtsc
                mov [rdi + 8*23], edx
                mov [rdi + 8*24], eax

                # Save the general purpose regs used in rdtsc
                mov rax, [rdi + 8*0]
                mov rdx, [rdi + 8*2]

                # Must be last since we are using RDI for VmRegs
                mov rdi, [rdi + 8*7] 

            1:
                # Get back address of registers
                # Exchange Guest RDI for address of VmRegs saved on the stack
                xchg rdi, [rsp]

                mov [rdi + 8*0], rax
                mov [rdi + 8*2], rdx

                # Save the current timecounter after
                rdtsc
                mov [rdi + 8*25], edx
                mov [rdi + 8*26], eax

                # Save current cr8
                # mov rax, cr8
                # mov [rdi + 8*29], rax

                mov [rdi + 8*1], rcx
                mov [rdi + 8*3], rbx
                mov [rdi + 8*5], rbp
                mov [rdi + 8*6], rsi

                # Pop the Guest RDI that was just placed on the stack
                pop rax
                mov [rdi + 8*7], rax
                mov rax, cr2
                mov [rdi + 8*4], rax

                mov [rdi + 8*8], r8
                mov [rdi + 8*9], r9
                mov [rdi + 8*10], r10
                mov [rdi + 8*11], r11
                mov [rdi + 8*12], r12
                mov [rdi + 8*13], r13
                mov [rdi + 8*14], r14
                mov [rdi + 8*15], r15

                # Set Guest RSP in VmRegs
                mov rax, 0x681c
                vmread rbx, rax
                mov [rdi + 8*16], rbx

                # Set Guest RIP in VmRegs
                mov rax, 0x681e
                vmread rbx, rax 
                mov [rdi + 8*17], rbx
                
                # Set Guest RFLAGS in VmRegs
                mov rax, 0x6820
                vmread rbx, rax 
                mov [rdi + 8*18], rbx

                # Save the guest xstate and restore the host xstate
                mov rdx, 0xffffffffffffffff
                mov rax, 0xffffffffffffffff
                mov rbx, [rdi + 8*21] # guest xstate
                xsave [rbx]
                mov rbx, [rdi + 8*22] # host xstate
                xrstor [rbx]

                # Return address of VmRegs back from the assembly
                mov rax, rdi

                # Restore all registers since everything was clobbered
                popf
                pop r15
                pop r14
                pop r13
                pop r12
                pop r11
                pop r10
                pop r9
                pop r8
                pop rbp
                pop rdx
                pop rcx
                pop rbx
            "# 
            : /* output */   // "={rax}"(result)
            : /* input */    "{rdi}"(regs_addr)
            : /* clobbers */ "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", 
                             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory", 
                             "cc"
            : /* options */ "volatile", "intel");
        }

        let time_end = time::rdtsc();
        result.push(time_end - time_start)
    }

    (result.iter().sum::<u64>() as usize / result.len()) as u64
}
