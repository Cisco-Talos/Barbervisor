use crate::msr::*;
use x86_64::registers::model_specific::Msr;

#[derive(Debug)]
pub struct PinCtls;

bitflags! {
    pub struct PinCtlsFlags: u64 {
        /// If this control is 1, external interrupts cause VM exits. Otherwise, they are delivered
        /// normally through the guest interrupt-descriptor table (IDT). If this control is 1, the
        /// value of RFLAGS.IF does not affect interrupt blocking.
        const EXTERNAL_INT_EXIT = 1 << 0;

        /// If this control is 1, external interrupts cause VM exits. Otherwise, they are delivered
        /// normally through the guest interrupt-descriptor table (IDT). If this control is 1, the
        /// value of RFLAGS.IF does not affect interrupt blocking.
        const NMI_EXIT = 1 << 3;

        /// If this control is 1, NMIs are never blocked and the “blocking by NMI” bit (bit 3) in
        /// the interruptibility-state field indicates “virtual-NMI blocking” (see Table 24-3).
        /// This control also interacts with the “NMI-window exiting” VM-execution control (see
        /// Section 24.6.2).
        const VIRTUAL_NMI = 1 << 5;

        /// If this control is 1, the VMX-preemption timer counts down in VMX non-root operation;
        /// see Section 25.5.1. A VM exit occurs when the timer counts down to zero; see Section
        /// 25.2.
        const ACTIVE_VMX_PREEMPTION_TIMER = 1 << 6;

        /// If this control is 1, the processor treats interrupts with the posted-interrupt
        /// notification vector (see Section 24.6.8) specially, updating the virtual-APIC page with
        /// posted-interrupt requests (see Section 29.6).
        const PROCESS_POSTED_INT = 1 << 7;
    }
}

impl PinCtls {
    pub fn read() -> PinCtlsFlags {
        let result = Self::read_raw();
        PinCtlsFlags::from_bits_truncate(result >> 32 | result)
    }

    pub fn read_raw() -> u64 {
        unsafe { Msr::new(IA32_VMX_PINBASED_CTLS).read() }
    }

    /// Write Pin based processor flags.
    ///
    /// Preserves the value of reserved fields. Unsafe because it's possible to violate memory
    /// safety by e.g. disabling paging.
    pub unsafe fn write(flags: PinCtlsFlags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(PinCtlsFlags::all().bits());
        let new_value = reserved | flags.bits();
        Self::write_raw(new_value);
    }

    pub unsafe fn write_raw(value: u64) {
        Msr::new(IA32_VMX_PINBASED_CTLS).write(value)
    }
}

#[derive(Debug)]
pub struct ProcCtls;

bitflags! {
    /// Documentation from
    /// Table 24-6.  efinitions of Primary Processor-Based VM-Execution Controls
    /// Intel 24.6.2
    pub struct ProcCtlsFlags: u64 {
        /// If this control is 1, a VM exit occurs at the beginning of any instruction
        /// if RFLAGS.IF = 1 and there are no other blocking of interrupts (see Section 24.4.2)
        const INTERRUPT_WINDOW_EXIT =  1 << 2;

        /// This control determines whether executions of RDTSC, executions of RDTSCP, and
        /// executions of RDMSR that read from the IA32_TIME_STAMP_COUNTER MSR return a value
        /// modified by the TSC offset field (see Section 24.6.5 and Section 25.3).
        const USE_TSC_OFFSETTING= 1 << 3;

        /// This control determines whether executions of HLT cause VM exits.
        const HLT_EXIT = 1 << 7;

        /// This determines whether executions of INVLPG cause VM exits.
        const INVLPG_EXIT = 1 << 9;

        /// This control determines whether executions of MWAIT cause VM exits.
        const MWAIT_EXIT = 1 << 10;

        /// This control determines whether executions of RDPMC cause VM exits.
        const RDPMC_EXIT = 1 << 11;

        /// This control determines whether executions of RDTSC and RDTSCP cause VM exits.
        const RDTSC_EXIT = 1 << 12;

        /// In conjunction with the CR3-target controls (see Section 24.6.7), this control
        /// determines whether executions of MOV to CR3 cause VM exits. See Section 25.1.3.
        const CR3_LOAD_EXIT =  1 << 15;

        /// This control determines whether executions of MOV from CR3 cause VM exits.
        const CR3_STORE_EXIT = 1 << 16;

        /// This control determines whether executions of MOV to CR8 cause VM exits.
        const CR8_LOAD_EXIT = 1 << 19;

        /// This control determines whether executions of MOV from CR8 cause VM exits.
        const CR8_STORE_EXIT = 1 << 20;

        /// Setting this control to 1 enables TPR virtualization and other APIC-virtualization
        /// features. See Chapter 29.
        const USE_TPR_SHADOW = 1 << 21;

        /// If this control is 1, a VM exit occurs at the beginning of any instruction if there is
        /// no virtual-NMI blocking (see Section 24.4.2).
        const NMI_WINDOW_EXIT = 1 << 22;

        /// This control determines whether executions of MOV DR cause VM exits
        const MOV_DR_EXIT = 1 << 23;

        /// This control determines whether executions of I/O instructions (IN,INS/INSB/INSW/INSD,
        /// OUT, and OUTS/OUTSB/OUTSW/OUTSD) cause VM exits.
        const UNCONDITIONAL_IO_EXIT = 1 << 24;

        /// This control determines whether I/O bitmaps are used to restrict executions of I/O
        /// instructions (see Section 24.6.4 and Section 25.1.3).
        /// For this control, “0” means “do not use I/O bitmaps” and “1” means “use I/O bitmaps.”
        /// If the I/O bitmaps are used, the setting of the “unconditional I/O exiting” control is
        /// ignored.
        const USE_IO_BITMAPS = 1 << 25;

        /// If this control is 1, the monitor trap flag debugging feature is enabled. See Section
        /// 25.5.2.
        const MONITOR_TRAP = 1 << 27;

        /// This control determines whether MSR bitmaps are used to control execution of the RDMSR
        /// and WRMSR instructions (see Section 24.6.9 and Section 25.1.3).For this control, “0”
        /// means “do not use MSR bitmaps” and “1” means “use MSR bitmaps.” If the MSR bitmaps are
        /// not used, all executions of the RDMSR and WRMSR instructions cause VM exits.
        const USE_MSR_BITMAPS = 1 << 28;

        /// This control determines whether executions of MONITOR cause VM exits
        const MONITOR_EXIT = 1 << 29;

        /// This control determines whether executions of PAUSE cause VM exits.
        const PAUSE_EXIT = 1 << 30;

        /// This control determines whether the secondary processor-based VM-execution controls
        /// are used. If this control is 0, the logical processor operates as if all the secondary
        /// processor-based VM-execution controls were also 0.
        const SECONDARY = 1 << 31;
    }
}

impl ProcCtls {
    pub fn read() -> ProcCtlsFlags {
        let result = Self::read_raw();
        ProcCtlsFlags::from_bits_truncate(result >> 32 | (result & 0xffff_ffff))
    }

    pub fn read_raw() -> u64 {
        unsafe { Msr::new(IA32_VMX_PROCBASED_CTLS).read() }
    }

    /// Write Pin based processor flags.
    ///
    /// Preserves the value of reserved fields. Unsafe because it's possible to violate memory
    /// safety by e.g. disabling paging.
    pub unsafe fn write(flags: ProcCtlsFlags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(PinCtlsFlags::all().bits());
        let new_value = reserved | flags.bits();
        Self::write_raw(new_value);
    }

    pub unsafe fn write_raw(value: u64) {
        Msr::new(IA32_VMX_PROCBASED_CTLS).write(value)
    }
}

#[derive(Debug)]
pub struct ProcCtls2;

bitflags! {
    pub struct ProcCtls2Flags: u64 {
        /// If this control is 1, the logical processor treats specially accesses to the page with
        /// the APIC-access address. See Section 29.4.
        const VIRTUALIZE_APIC = 1 << 0;

        /// If this control is 1, extended page tables (EPT) are enabled. See Section 28.2.
        const ENABLE_EPT = 1 << 1;

        /// This control determines whether executions of LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT,
        /// and STR cause VM exits.
        const DESCRIPTOR_TABLE_EXIT = 1 << 2;

        /// If this control is 0, any execution of RDTSCP causes an invalid-opcode exception (#UD)
        const ENABLE_RDTSP = 1 << 3;

        /// If this control is 1, the logical processor treats specially RDMSR and WRMSR to APIC
        /// MSRs (in the range 800H–8FFH). See Section 29.5.
        const VIRTUALIZE_x2APIC_MODE = 1 << 4;

        /// If this control is 1, cached translations of linear addresses are associated with a
        /// virtual-processor identifier (VPID). See Section 28.1.
        const ENABLE_VPID = 1 << 5;

        /// This control determines whether executions of WBINVD cause VM exits.
        const WBINVD_EXIT = 1 << 6;

        /// This control determines whether guest software may run in unpaged protected mode or
        /// in real-address mode
        const UNRESTRICTED_GUEST = 1 << 7;

        /// If this control is 1, the logical processor virtualizes certain APIC accesses. See
        /// Section 29.4 and Section 29.5.
        const APIC_REGISTER_VIRTUALIZATION = 1 << 8;

        /// This controls enables the evaluation and delivery of pending virtual interrupts as well
        /// as the emulation of writes to the APIC registers that control interrupt prioritization.
        const VIRTUAL_INTERRUPT_DELIVERY = 1 << 9;

        ///  This control determines whether a series of executions of PAUSE can cause a VM exit
        ///  (see Section 24.6.13 and Section 25.1.3).
        const PAUSE_LOOP_EXIT = 1 << 10;

        /// This control determines whether executions of RDRAND cause VM exits.
        const RDRAND_EXIT = 1 << 11;

        /// If this control is 0, any execution of INVPCID causes a #UD.
        const ENABLE_INVPCID = 1 << 12;

        /// Setting this control to 1 enables use of the VMFUNC instruction in VMX non-root
        /// operation. See Section 25.5.5.
        const ENABLE_VM_FUNCTIONS = 1 << 13;

        /// If this control is 1, executions of VMREAD and VMWRITE in VMX non-root operation may
        /// access a shadow VMCS (instead of causing VM exits). See Section 24.10 and Section 30.3.
        const VMCS_SHADOWING = 1 << 14;

        /// If this control is 1, executions of ENCLS consult the ENCLS-exiting bitmap to determine
        /// whether the instruction causes a VM exit. See Section 24.6.16 and Section 25.1.3.
        const ENABLE_ENCLS_EXIT = 1 << 15;

        /// This control determines whether executions of RDSEED cause VM exits
        const RDSEED_EXIT = 1 << 16;

        /// If this control is 1, an access to a guest-physical address that sets an EPT dirty bit
        /// first adds an entry to the page-modification log. See Section 28.2.6.
        const ENABLE_PML = 1 << 17;

        /// If this control is 1, EPT violations may cause virtualization exceptions (#VE) instead
        /// of VM exits. See Section 25.5.6.
        const EPT_VIOLATION_VIRT_EXCEPT = 1 << 18;

        /// If this control is 1, Intel Processor Trace suppresses from PIPs an indication that the
        /// processor was in VMX non-root operation and omits a VMCS packet from any PSB+ produced
        /// in VMX non-root operation (see Chapter 35).
        const CONCEAL_VMX_FROM_PT = 1 << 19;

        /// If this control is 0, any execution of XSAVES or XRSTORS causes a #UD.
        const ENABLE_XSAVES_XRSTORS  = 1 << 20;

        const RESERVED21 = 1 << 21;

        /// If this control is 1, EPT execute permissions are based on whether the linear address
        /// being accessed is supervisor mode or user mode. See Chapter 28.
        const MODE_BASED_EXEC_CONTROL_EPT = 1 << 22;

        /// If this control is 1, EPT write permissions may be specified at the granularity of 128
        /// bytes. See Section 28.2.4.
        const SUB_PAGE_WRITE_PERM_EPT = 1 << 23;

        /// If this control is 1, all output addresses used by Intel Processor Trace are treated as
        /// guest-physical addresses and translated using EPT. See Section 25.5.4.
        const INTEL_PT_USE_GUEST_PHYS_ADDR = 1 << 24;

        /// This control determines whether executions of RDTSC, executions of RDTSCP, and
        /// executions of RDMSR that read from the IA32_TIME_STAMP_COUNTER MSR return a value
        /// modified by the TSC multiplier field (see Section 24.6.5 and Section 25.3).
        const USE_TSC_SCALING = 1 << 25;

        /// If this control is 0, any execution of TPAUSE, UMONITOR, or UMWAIT causes a #UD.
        const ENABLE_USER_PAUSE_WAIT = 1 << 26;

        const RESERVED27 = 1 << 27;

        /// If this control is 1, executions of ENCLV consult the ENCLV-exiting bitmap to determine
        /// whether the instruction causes a VM exit. See Section 24.6.17 and Section 25.1.3.
        const ENABLE_ENCLV_EXIT = 1 << 28;
        const RESERVED29 = 1 << 29;
        const RESERVED30 = 1 << 30;
        const RESERVED31 = 1 << 31;
    }
}

impl ProcCtls2 {
    pub fn read() -> ProcCtls2Flags {
        let result = Self::read_raw();
        ProcCtls2Flags::from_bits_truncate(result >> 32 | result)
    }

    pub fn read_raw() -> u64 {
        unsafe { Msr::new(IA32_VMX_PROCBASED_CTLS2).read() }
    }

    /// Write Pin based processor flags.
    ///
    /// Preserves the value of reserved fields. Unsafe because it's possible to violate memory
    /// safety by e.g. disabling paging.
    pub unsafe fn write(flags: ProcCtls2Flags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(ProcCtls2Flags::all().bits());
        let new_value = reserved | flags.bits();
        Self::write_raw(new_value);
    }

    pub unsafe fn write_raw(value: u64) {
        Msr::new(IA32_VMX_PROCBASED_CTLS2).write(value)
    }
}

#[derive(Debug)]
pub struct EntryCtls;

bitflags! {
    pub struct EntryCtlsFlags: u64 {
        /// This control determines whether DR7 and the IA32_DEBUGCTL MSR are loaded on VM entry.
        /// The first processors to support the virtual-machine extensions supported only the 1-setting
        /// of this control.
        const LOAD_DEBUG_CONTROLS= 1 << 2;

        /// On processors that support Intel 64 architecture, this control determines whether the
        /// logical processor is in IA-32e mode after VM entry. Its value is loaded into
        /// IA32_EFER.LMA as part of VM entry. This control must be 0 on processors that do not
        /// support Intel 64 architecture.
        const IA32_MODE_GUEST = 1 << 9;

        /// This control determines whether the logical processor is in system-management mode
        /// (SMM) after VM entry. This control must be 0 for any VM entry from outside SMM.
        const ENTRY_TO_SMM = 1 << 10;

        /// If set to 1, the default treatment of SMIs and SMM is in effect after the VM entry (see
        /// Section 34.15.7). This control must be 0 for any VM entry from outside SMM.
        const DEACTIVATE_TO_DUAL_MONITOR_TREATMENT = 1 << 11;

        /// This control determines whether the IA32_PERF_GLOBAL_CTRL MSR is loaded on VM entry.
        const LOAD_IA32_PERF_GLOBAL_CTRL = 1 << 13;

        /// This control determines whether the IA32_PAT MSR is loaded on VM entry.
        const LOAD_IA32_PAT = 1 << 14;

        /// This control determines whether the IA32_EFER MSR is loaded on VM entry.
        const LOAD_IA32_EFER = 1 << 15;

        /// This control determines whether the IA32_BNDCFGS MSR is loaded on VM entry.
        const LOAD_IA32_BNDCFGS = 1 << 16;

        /// If this control is 1, Intel Processor Trace does not produce a paging information
        /// packet (PIP) on a VM entry or a VMCS packet on a VM entry that returns from SMM (see
        /// Chapter 35).
        const CONCEAL_VMX_FROM_PT = 1 << 17;

        /// This control determines whether the IA32_RTIT_CTL MSR is loaded on VM entry.
        const LOAD_IA32_RTIT_CTL = 1 << 18;
    }
}

impl EntryCtls {
    pub fn read() -> EntryCtlsFlags {
        let result = Self::read_raw();
        EntryCtlsFlags::from_bits_truncate(result >> 32 | result)
    }

    pub fn read_raw() -> u64 {
        unsafe { Msr::new(IA32_VMX_ENTRY_CTLS).read() }
    }

    /// Write Pin based processor flags.
    ///
    /// Preserves the value of reserved fields. Unsafe because it's possible to violate memory
    /// safety by e.g. disabling paging.
    pub unsafe fn write(flags: EntryCtlsFlags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(EntryCtlsFlags::all().bits());
        let new_value = reserved | flags.bits();
        Self::write_raw(new_value);
    }

    pub unsafe fn write_raw(value: u64) {
        Msr::new(IA32_VMX_ENTRY_CTLS).write(value)
    }
}

/*
impl From<EntryCtls> for u64 {
    fn from(ctls: EntryCtls) -> u64 {
        ctls.bits() as u64
    }
}

impl From<EntryCtls> for u32 {
    fn from(ctls: EntryCtls) -> u32 {
        ctls.bits()
    }
}
*/

#[derive(Debug)]
pub struct ExitCtls;

bitflags! {
    pub struct ExitCtlsFlags: u32 {
        /// This control determines whether DR7 and the IA32_DEBUGCTL MSR are saved on VM exit.The
        /// first processors to support the virtual-machine extensions supported only the 1-setting
        /// of this control.
        const SAVE_DEBUG_CONTROLS = 1 << 2;

        /// On processors that support Intel 64 architecture, this control determines whether a
        /// logical processor is in 64-bit mode after the next VM exit. Its value is loaded into
        /// CS.L, IA32_EFER.LME, and IA32_EFER.LMA on every VM exit.1This control must be 0 on
        /// processors that do not support Intel 64 architecture.
        const HOST_ADDRESS_SPACE_SIZE = 1 << 9;

        /// This control determines whether the IA32_PERF_GLOBAL_CTRL MSR is loaded on VM exit.
        const LOAD_IA32_PERF_GLOBAL_CTRL = 1 << 12;

        /// This control affects VM exits due to external interrupts:
        /// •   If such a VM exit occurs and this control is 1, the logical processor acknowledges the
        /// interrupt controller, acquiring the interrupt’s vector. The vector is stored in the VM-exit
        /// interruption-information field, which is marked valid.
        /// •   If such a VM exit occurs and this control is 0, the interrupt is not acknowledged and
        /// the VM-exit interruption-information field is marked invalid.
        const ACKNOWLEDGE_INTERRUPT = 1 << 15;

        /// This control determines whether the IA32_PAT MSR is saved on VM exit.
        const SAVE_IA32_PAT = 1 << 18;

        /// This control determines whether the IA32_PAT MSR is loaded on VM exit.
        const LOAD_IA32_PAT = 1 << 19;

        /// This control determines whether the IA32_EFER MSR is saved on VM exit.
        const SAVE_IA32_EFER = 1 << 20;

        /// This control determines whether the IA32_EFER MSR is loaded on VM exit.
        const LOADS_IA32_EFER = 1 << 21;

        /// This control determines whether the value of the VMX-preemption timer is saved on VM
        /// exit.
        const SAVE_VMX_PREEMPTION_TIMER_VALUE = 1 << 22;

        /// This control determines whether the IA32_BNDCFGS MSR is cleared on VM exit.
        const CLEAR_IA32_BNDCFGS = 1 << 23;

        /// If this control is 1, Intel Processor Trace does not produce a paging information packet
        /// (PIP) on a VM exit or a VMCS packet on an SMM VM exit (see Chapter 35).
        const CONCEAL_VMX_FROM_PT = 1 << 24;

        /// This control determines whether the IA32_RTIT_CTL MSR is cleared on VM exit.
        const CLEAR_IA32_RTIT_CTL = 1 << 25;
    }
}

impl ExitCtls {
    pub fn read() -> ExitCtlsFlags {
        let result = Self::read_raw();
        ExitCtlsFlags::from_bits_truncate((result >> 32 | result) as u32)
    }

    pub fn read_raw() -> u64 {
        unsafe { Msr::new(IA32_VMX_EXIT_CTLS).read() }
    }

    /// Write Pin based processor flags.
    ///
    /// Preserves the value of reserved fields. Unsafe because it's possible to violate memory
    /// safety by e.g. disabling paging.
    pub unsafe fn write(flags: ExitCtlsFlags) {
        let old_value = Self::read_raw();
        let reserved = old_value as u32 & !(ExitCtlsFlags::all().bits());
        let new_value = reserved | flags.bits();
        Self::write_raw(new_value.into());
    }

    pub unsafe fn write_raw(value: u64) {
        Msr::new(IA32_VMX_EXIT_CTLS).write(value)
    }
}

/*
impl From<ExitCtls> for u64 {
    fn from(ctls: ExitCtls) -> u64 {
        ctls.bits() as u64
    }
}

impl From<ExitCtls> for u32 {
    fn from(ctls: ExitCtls) -> u32 {
        ctls.bits()
    }
}
*/

bitflags! {
    pub struct MemoryAccess: u32 {
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
    }
}

#[derive(Debug)]
pub struct Cr4;

bitflags! {
    pub struct Cr4Flags: u64 {
        ///  Enables interrupt- and exception-handling extensions in virtual-8086 mode when set;
        ///  disables the extensions when clear. Use of the virtual mode extensions can improve the
        ///  performance of virtual-8086 applications by eliminating the overhead of calling the
        ///  virtual-8086 monitor to handle interrupts and exceptions that occur while executing an
        ///  8086 program and, instead, redirecting the interrupts and exceptions back to the 8086
        ///  program’s handlers. It also provides hardware support for a virtual interrupt flag
        ///  (VIF) to improve reliability of running 8086 programs in multi-tasking and
        ///  multiple-processor environments.
        const VIRTUAL_8086 = 1 << 0;

        /// Enables hardware support for a virtual interrupt flag (VIF) in protected mode when set;
        /// disables the VIF flag in protected mode when clear.
        /// See also: Section 20.4, “Protected-Mode Virtual Interrupts.”
        const PROTEDCTED_MODE_VIRTUAL_INTERRUPTS = 1 << 1;

        /// Restricts the execution of the RDTSC instruction to procedures running at privilege
        /// level 0 when set; allows RDTSC instruction to be executed at any privilege level when
        /// clear. This bit also applies to the RDTSCP instruction if supported (if
        /// CPUID.80000001H:EDX[27] = 1).
        const TIMESTAMP_DISABLE = 1 << 2;

        /// References to debug registers DR4 and DR5 cause an unde-fined opcode (#UD) exception to
        /// be generated when set; when clear, processor aliases references to regis-ters DR4 and
        /// DR5 for compatibility with software written to run on earlier IA-32 processors.
        const DEBUGGING_EXTENSIONS = 1 << 3;

        /// Enables 4-MByte pages with 32-bit paging when set; restricts 32-bit paging to pages of
        /// 4 KBytes when clear.
        const PAGE_SIZE_EXTENSIONS = 1 << 4;

        /// When set, enables paging to produce physical addresses with more than 32 bits.
        /// When clear, restricts physical addresses to 32 bits. PAE must be set before entering IA-32e mode.
        /// See also: Chapter 4, “Paging.”
        const PHYSICAL_ADDRESS_EXTENSION = 1 << 5;

        /// Enables the machine-check exception when set; disables the machine-check exception when clear.
        /// See also: Chapter 15, “Machine-Check Architecture.”
        const MACHINE_CHECK_ENABLE = 1 << 6;

        /// (Introduced in the P6 family processors.) Enables the global page feature when set;
        /// disables the global page feature when clear. The global page feature allows frequently used
        /// or shared pages to be marked as global to all users (done with the global flag, bit 8, in a
        /// page-direc-tory or page-table entry). Global pages are not flushed from the translation-lookaside
        /// buffer (TLB) on a task switch or a write to register CR3.When enabling the global page feature,
        /// paging must be enabled (by setting the PG flag in control register CR0) before the PGE flag is set.
        /// Reversing this sequence may affect program correctness, and processor performance will be impacted.
        /// See also: Section 4.10, “Caching Translation Information.”
        const PAGE_GLOBAL_ENABLE = 1 << 7;

        /// Enables execution of the RDPMC instruc-tion for programs or procedures running at any
        /// protection level when set; RDPMC instruction can be executed only at protection level 0
        /// when clear.
        const PERFORMANCE_MONITORING_COUNTER_ENABLE = 1 << 8;

        /// When set, this flag: (1) indicates to software that the operating system supports the
        /// use of the FXSAVE and FXRSTOR instructions, (2) enables the FXSAVE and FXRSTOR
        /// instructions to save and restore the contents of the XMM and MXCSR registers along with
        /// the contents of the x87 FPU and MMX registers, and (3) enables the processor to execute
        /// SSE/SSE2/SSE3/SSSE3/SSE4 instructions, with the exception of the PAUSE, PREFETCHh,
        /// SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
        const OS_SUPPORT_FOR_FXSAVE_FXRSTOR = 1 << 9;

        /// When set, indicates that the operating system supports the handling of unmasked SIMD
        /// floating-point exceptions through an exception handler that is invoked when a SIMD
        /// floating-point exception (#XM) is generated. SIMD floating-point exceptions are only
        /// generated by SSE/SSE2/SSE3/SSE4.1 SIMD floating-point instructions.
        const OS_SUPPORT_FOR_UNMASKED_SIMD = 1 << 10;

        /// When set, the following instructions cannot be executed if CPL > 0: SGDT, SIDT, SLDT,
        /// SMSW, and STR. An attempt at such execution causes a general-protection exception
        /// (#GP).
        const USER_MODE_INSTRUCTION_PROTECTION = 1 << 11;

        /// Enables VMX operation when set. See Chapter 23, “Introduction to Virtual Machine Extensions.”
        const VMX_ENABLE = 1 << 13;

        /// Enables SMX operation when set. See Chapter 6, “Safer Mode Exten-sions Reference” of
        /// Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 2D.
        const SMX_ENABLE = 1 << 14;

        /// Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
        const FSGSBASE_BIT = 1 << 16;

        /// Enables process-context identifiers (PCIDs) when set. See Section 4.10.1,
        /// “Process-Context Identifiers (PCIDs)”. Can be set only in IA-32e mode (if IA32_EFER.LMA
        /// = 1).
        const PCID_ENABLE_BIT = 1 << 17;

        /// When set, this flag: (1) indi-cates (via CPUID.01H:ECX.OSXSAVE[bit 27]) that the
        /// operating system supports the use of the XGETBV, XSAVE and XRSTOR instructions by
        /// general software; (2) enables the XSAVE and XRSTOR instructions to save and restore the
        /// x87 FPU state (including MMX registers), the SSE state (XMM registers and MXCSR), along
        /// with other processor extended states enabled in XCR0; (3) enables the processor to
        /// execute XGETBV and XSETBV instructions in order to read and write XCR0. See Section 2.6
        /// and Chapter 13, “System Programming for Instruction Set Extensions and Processor
        /// Extended States”.
        const XSAVE_PROCESSOR_EXTENDED_STATES_ENABLE_BIT = 1 << 18;

        /// Enables supervisor-mode execution prevention (SMEP) when set. See Section 4.6, “Access
        /// Rights”.
        const SMEP_ENABLE_BIT = 1 << 20;

        /// Enables supervisor-mode access prevention (SMAP) when set. See Section 4.6, “Access
        /// Rights.”
        const SMAP_ENABLE_BIT = 1 << 21;

        /// Enables 4-level paging to associate each linear address with a protection key. The PKRU
        /// register specifies, for each protection key, whether user-mode linear addresses with
        /// that protection key can be read or written. This bit also enables access to the PKRU
        /// register using the RDPKRU and WRPKRU instructions.
        const PROTECTION_KEY_ENABLE_BIT = 1 << 22;
    }
}

impl Cr4 {
    pub fn read() -> Cr4Flags {
        Cr4Flags::from_bits_truncate(Self::read_raw())
    }

    pub fn read_raw() -> u64 {
        let value: u64;
        unsafe {
           llvm_asm!("mov %cr4, $0" : "=r" (value));
        }
        value
    }

    /// Write Cr4 flags.
    ///
    /// Preserves the value of reserved fields. Unsafe because it's possible to violate memory
    /// safety by e.g. disabling paging.
    pub unsafe fn write(flags: Cr4Flags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(Cr4Flags::all().bits());
        let new_value = reserved | flags.bits();
        Self::write_raw(new_value);
    }

    pub unsafe fn write_raw(value: u64) {
       llvm_asm!("mov $0, %cr4" :: "r" (value) : "memory");
    }

    pub unsafe fn insert(flags: Cr4Flags) {
        let mut orig_flags = Self::read();
        orig_flags.insert(flags);
        Self::write(orig_flags);
    }
}

pub struct PageFaultErrorCode {
    value: u32,
}

impl From<u32> for PageFaultErrorCode {
    fn from(value: u32) -> PageFaultErrorCode {
        PageFaultErrorCode { value: value }
    }
}

impl core::fmt::Display for PageFaultErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let _ = match self.value & 1 {
            0 => write!(f, "NOT Present | "),
            1 => write!(f, "IS  Present | "),
            _ => write!(f, "???"),
        };

        let _ = match (self.value >> 1) & 1 {
            0 => write!(f, "READ  | "),
            1 => write!(f, "WRITE | "),
            _ => write!(f, "???"),
        };

        let _ = match (self.value >> 2) & 1 {
            0 => write!(f, "ROOT | "),
            1 => write!(f, "USER | "),
            _ => write!(f, "???"),
        };

        let _ = match (self.value >> 3) & 1 {
            0 => write!(f, "NOT ReservedBit | "),
            1 => write!(f, "BAD ReservedBit | "),
            _ => write!(f, "???"),
        };

        let _ = match (self.value >> 4) & 1 {
            0 => write!(f, "NOT Instr Fetch | "),
            1 => write!(f, "IS  Instr Fetch | "),
            _ => write!(f, "???"),
        };

        let _ = match (self.value >> 5) & 1 {
            0 => write!(f, "NOT Protection Keys | "),
            1 => write!(f, "IS  Protection Keys | "),
            _ => write!(f, "???"),
        };

        let _ = match (self.value >> 6) & 1 {
            0 => write!(f, "NOT SGX\n"),
            1 => write!(f, "IS  SGX\n"),
            _ => write!(f, "???\n"),
        };
        Ok(())
    }
}

bitflags! {
    pub struct EntryFlags: u64 {
        const PRESENT =         1 << 0;
        const WRITABLE =        1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const WRITE_THROUGH =   1 << 3;
        const NO_CACHE =        1 << 4;
        const ACCESSED =        1 << 5;
        const DIRTY =           1 << 6;
        const HUGE_PAGE =       1 << 7;
        const GLOBAL =          1 << 8;
        const NO_EXECUTE =      1 << 63;
    }
}

bitflags! {
    pub struct EptEntryFlags: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        /// If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has
        /// accessed the 512-GByte region controlled by this entry (see Section 28.2.4).
        /// Ignored if bit 6 of EPTP is 0
        const ACCESSED = 1 << 8;
        /// If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has
        /// accessed the 512-GByte region controlled by this entry (see Section 28.2.4).
        /// Ignored if bit 6 of EPTP is 0
        const DIRTY = 1 << 9;
        /// Execute access for user-mode linear addresses. If the “mode-based execute control for EPT”
        /// VM-execution control is 1, indicates whether instruction fetches are allowed from user-mode
        /// linear addresses in the 512-GByte region controlled by this entry.
        /// If that control is 0, this bit is ignored.
        const EXECUTE2 = 1 << 10;
    }
}
