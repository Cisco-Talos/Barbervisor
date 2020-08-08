use crate::vmxflags::*;
use msr::*;
use x86_64::registers::control::*;
use x86_64::registers::model_specific::Msr;

/// Struct for setting the VMXON region
#[repr(C)]
pub struct VMXON {
    revision_id: u32,
    data: [u8; 4092],
}

impl VMXON {
    fn new(id: u32) -> VMXON {
        VMXON {
            revision_id: id,
            data: [0; 4092],
        }
    }
}

pub struct VmcsRegs {
    pub es: VmcsSreg,
    pub cs: VmcsSreg,
    pub ss: VmcsSreg,
    pub ds: VmcsSreg,
    pub fs: VmcsSreg,
    pub gs: VmcsSreg,
    pub ldt: VmcsSreg,
    pub tr: VmcsSreg,
    pub gdtr: VmcsDesc,
    pub idtr: VmcsDesc,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub dr7: u64,
    pub rflags: u64,
}

impl VmcsRegs {
    pub fn new() -> VmcsRegs {
        VmcsRegs {
            es: VmcsSreg::new(),
            cs: VmcsSreg::new(),
            ss: VmcsSreg::new(),
            ds: VmcsSreg::new(),
            fs: VmcsSreg::new(),
            gs: VmcsSreg::new(),
            ldt: VmcsSreg::new(),
            tr: VmcsSreg::new(),
            gdtr: VmcsDesc::new(),
            idtr: VmcsDesc::new(),
            cr0: 0,
            cr3: 0,
            cr4: 0,
            dr7: 0,
            rflags: 0,
        }
    }
}

#[repr(packed)]
/// VMCS Descriptor
pub struct VmcsDesc {
    pub limit: u16,
    pub base: u32,
}

impl VmcsDesc {
    pub fn new() -> VmcsDesc {
        VmcsDesc { limit: 0, base: 0 }
    }
}

/// VMCS Segment
pub struct VmcsSreg {
    pub sel: u16,
    pub limit: u32,
    pub acr: u32,
    pub base: u32,
}

impl VmcsSreg {
    pub fn new() -> VmcsSreg {
        VmcsSreg {
            sel: 0,
            limit: 0,
            acr: 0,
            base: 0,
        }
    }
}

#[repr(packed)]
pub struct SegmentDesc {
    limit_15_0: u16,
    base_15_0: u16,
    base_23_16: u8,
    flags: u8,
    limit_19_16_flags: u8,
    base_31_24: u8,
}

impl SegmentDesc {
    pub fn get_base(&self) -> u32 {
        ((self.base_31_24 as u32) << 24) | ((self.base_23_16 as u32) << 16) | self.base_15_0 as u32
    }
}

#[repr(C)]
pub struct VMCS {
    revision_id: u32,
    data: [u8; 4092],
}

impl VMCS {
    fn new(id: u32) -> VMCS {
        VMCS {
            revision_id: id,
            data: [0; 4092],
        }
    }
}

/// Wrapper for CPUID
pub fn cpuid(eax: u32) -> u32 {
    let res: u32;
    unsafe {
        llvm_asm!("cpuid"        :      // Assembly
             "={ecx}"(res)  :      // Output
             "{eax}"(eax)   :      // Input
             "eax", "ebx", "ecx", "edx"    :      // Clobbered registers
             "volatile", "intel"); // Options
    }
    res
}

/// Wrapper for VMXON
pub fn vmxon(ptr: u64) {
    unsafe {
        llvm_asm!("vmxon $0"          :      // Assembly
             /* No Output */     :      // Output
             "m"(ptr)            :      // Input
             /* No Clobbered */  :      // Clobbered registers
             "volatile", "intel"); // Options
    }
}

/// Wrapper for VMCLEAR
pub fn vmclear(ptr: u64) {
    unsafe {
        llvm_asm!("vmclear $0\n" : // Assembly
             /* No Output */: // Output
             "m"(ptr) : // Input
             /* No clobbered */ : // Clobbered regs
             "volatile", "intel"); // Options
    }
}

/// Wrapper for VMPTRLD
pub fn vmptrld(ptr: u64) {
    unsafe {
        llvm_asm!("vmptrld $0\n" : // Assembly
             /* No Output */: // Output
             "m"(ptr) : // Input
             /* No clobbered */: // Clobbered regs
             "volatile", "intel"); // Options
    }
}

/// Wrapper for VMWRITE
pub fn vmwrite(index: u32, value: u64) {
    unsafe {
        llvm_asm!("vmwrite rax, rbx" : // Assembly
             /* No Output */: // Output
             "{rax}"(index),"{rbx}"(value) : // Input
             "rax", "rbx": // Clobbered regs 
             "volatile", "intel"); // Options
    }
}

/// Wrapper for VMREAD
pub fn vmread(index: u32) -> u64 {
    let value: u64;
    unsafe {
        llvm_asm!("vmread rbx, rax" : // Assembly
             "={rbx}"(value) : // Output
             "{rax}"(index) : // Input
             "rax", "rbx": // Clobbered regs 
             "volatile", "intel"); // Options
    }
    value
}

fn check_vmx() -> bool {
    let res = cpuid(1);
    res & (1 << 5) != 0
}

fn enable_vmx_cr4() {
    unsafe {
        Cr4::insert(Cr4Flags::VMX_ENABLE);
    }
}

fn check_secondary_controls() -> bool {
    /* Checks the 31 bit of IA32_VMX_PROCBASED_CTLS to see if secondary
     * controls are enabled. Secondary controls is where the EPT enabled
     * bit is held */

    unsafe { ProcCtls::read().contains(ProcCtlsFlags::SECONDARY) }
}

fn has_vmx() -> bool {
    /* Check to see if EPT is enabled by checking the following:
     * IA32_VMX_PROCBASED_CTLS:31 == 1
     * IA32_VMX_PROCBASED_CTLS2:1 == 1
     */

    if check_vmx() {
        println!("VMX is supported");
    } else {
        println!("ERROR ERROR ERROR: VMX is not supported in CPUID");
        loop {}
    }

    if !check_secondary_controls() {
        println!("ERROR ERROR ERROR: Secondary controls not enabled.. cannot check EPT");
        loop {}
    } else {
        println!("CTLS Secondary controls enabled.. checking EPT now..");
    }

    let ctls2 = ProcCtls2::read();

    if ctls2.contains(ProcCtls2Flags::ENABLE_EPT) {
        println!("[*] EPT IS supported");
    } else {
        println!("[!] EPT is NOT supported");
        return false;
    }

    if ctls2.contains(ProcCtls2Flags::UNRESTRICTED_GUEST) {
        println!("[*] Unrestricted guest is ENABLED")
    } else {
        println!("[!] Unrestricted guest is DISABLED");
        return false;
    }
    true
}

fn enable_vmxon() {
    unsafe {
        let res = Msr::new(IA32_FEATURE_CONTROL).read();

        let mut feature_control = FeatureControl::from_bits_truncate(res as u32);
        println!("Res: {:#b}", res);
        println!("Feature Control: {:?}", feature_control);

        if feature_control.contains(FeatureControl::LOCK) {
            if feature_control.contains(FeatureControl::VMXON) {
                println!("VMXON is allowed! :)");
            } else {
                println!("VMXON is disabled :(");
            }
        } else {
            feature_control.toggle(FeatureControl::LOCK);
            feature_control.toggle(FeatureControl::VMXON);
            println!("Old value: {:?}", res);
            let new_value = res | (feature_control.bits() as u64);
            println!("New value: {:?}", new_value);

            println!("ZZ Attempting to enable VMXON... {:?}", feature_control);
            Msr::new(IA32_FEATURE_CONTROL).write(new_value);
            println!("Made it!");

            println!("VMXON Enabled!");
            // let res = Msr::new(IA32_FEATURE_CONTROL).read();
            // println!("Feature Control AFTER: {:#b}", res);
            // println!("Feature Control AFTER: {:?}", res);
        }
    }
}

/*
 * Apply FIXED bits for cr0 and cr4 for this processor
 */
fn set_vmx_capabilities() {
    // Apply FIXED bits
    unsafe {
        let cr0_0 = Msr::new(IA32_VMX_CR0_FIXED0).read() as u64;
        let cr0_1 = Msr::new(IA32_VMX_CR0_FIXED1).read() as u64;

        let mut cr0_bits = Cr0::read().bits();
        println!("cr0 before: {:?}", Cr0::read());

        cr0_bits = cr0_bits & cr0_1;
        cr0_bits = cr0_bits | cr0_0;
        println!("cr0 after: {:?}", Cr0::read());

        let cr0 = Cr0Flags::from_bits(cr0_bits)
            .expect("[set_vmx_capabilities] Unable to parse cr0 from_bits");
        Cr0::write(cr0);

        // Apply FIXED bits
        let cr4_0 = Msr::new(IA32_VMX_CR4_FIXED0).read() as u64;
        let cr4_1 = Msr::new(IA32_VMX_CR4_FIXED1).read() as u64;

        let mut cr4_bits = Cr4::read().bits();
        println!("cr4 before: {:?}", Cr4::read());

        cr4_bits = cr4_bits & cr4_1;
        cr4_bits = cr4_bits | cr4_0;
        println!("cr4 after: {:?}", Cr4::read());

        let cr4 = Cr4Flags::from_bits(cr4_bits)
            .expect("[set_vmx_capabilities] Unable to parse cr4 from_bits");
        Cr4::write(cr4);
    }
}

pub fn init() {
    has_vmx();
    enable_vmxon();
    set_vmx_capabilities();
    enable_vmx_cr4();
    println!("---------- VMX INITIALIZED ----------");
}

pub fn read_es() -> u16 {
    let res: u16;
    unsafe {
        llvm_asm!("mov $0, es\n" : // Assembly
             "=r"(res)   : // Output
             /* No input */ : // Input
                       : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_cs() -> u16 {
    let res: u16;
    unsafe {
        llvm_asm!("mov $0, cs\n" : // Assembly
             "=r"(res)   : // Output
             /* No input */ : // Input
                       : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_ss() -> u16 {
    let res: u16;
    unsafe {
        llvm_asm!("mov $0, ss\n" : // Assembly
             "=r"(res)   : // Output
             /* No input */ : // Input
                       : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_ds() -> u16 {
    let res: u16;
    unsafe {
        llvm_asm!("mov $0, ds\n" : // Assembly
             "=r"(res)   : // Output
             /* No input */ : // Input
                       : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_fs() -> u16 {
    let res: u16;
    unsafe {
        llvm_asm!("mov $0, fs\n" : // Assembly
             "=r"(res)   : // Output
             /* No input */ : // Input
                       : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_gs() -> u16 {
    let res: u16;
    unsafe {
        llvm_asm!("mov $0, gs\n" : // Assembly
             "=r"(res)   : // Output
             /* No input */ : // Input
                       : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_dr7() -> u64 {
    let res: u64;
    unsafe {
        llvm_asm!("mov $0, dr7\n" : // Assembly
             "=r"(res)   : // Output
             /* No input */ : // Input
             /* Clobbered */: // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_ldt() -> u16 {
    let res: u16;
    unsafe {
        llvm_asm!("sldt $0\n" : // Assembly
             "=r"(res)   : // Output
             /* No input */ : // Input
             "ax"           : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_tr() -> u16 {
    let res: u16;
    unsafe {
        llvm_asm!("str $0;\n" : // Assembly
             "=r" (res)   : // Output
             /* No input */ : // Input
             "ax"           : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn load_segment_limit(selector: u16) -> u32 {
    // let limit: u16;
    let limit: u32;
    unsafe {
        llvm_asm!("lsl $0, $1\n" : // Assembly
             "=r"(limit)   : // Output
             "r"(selector as u32): // Input
                       : // Clobbered regs
             "volatile", "intel"); // Options
    }
    limit
}

pub fn load_segment_access_rights(selector: u16) -> u32 {
    let limit: u32;
    unsafe {
        llvm_asm!("lar $0, $1\n" : // Assembly
             "=r"(limit)   : // Output
             "r"(selector as u32): // Input
                      : // Clobbered regs
             "volatile", "intel"); // Options
    }
    limit
}

pub fn get_segment_access_rights(selector: u16) -> u32 {
    if !(selector == 0) {
        return 0x10000 as u32;
    }

    let limit = load_segment_access_rights(selector);
    (limit >> 8) & 0xff0f
}

pub fn read_gdt() -> VmcsDesc {
    let res: VmcsDesc = VmcsDesc::new();
    let addr: u64 = &res as *const _ as u64;

    unsafe {
        llvm_asm!("sgdt [$0]\n" : // Assembly
             /* No Output */ : // Output
             "r"(addr) : // Input
             "memory" : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_idt() -> VmcsDesc {
    let res: VmcsDesc = VmcsDesc::new();
    let addr: u64 = &res as *const _ as u64;

    unsafe {
        llvm_asm!("sidt [$0]\n" : // Assembly
             /* No Output */ : // Output
             "r"(addr) : // Input
             "memory" : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn read_rflags() -> u64 {
    let mut res: u64 = 0;
    // let mut addr: u64 = &res as *const _ as u64;

    unsafe {
        llvm_asm!("pushfq ; pop $0\n" : // Assembly
             "=r"(res) : // Output
             /* No Input */: // Input
             "memory" : // Clobbered regs
             "volatile", "intel"); // Options
    }
    res
}

pub fn get_segment_base(gdtbase: u32, ldt: u16, selector: u16) -> u32 {
    if selector == 0 {
        // println!("Selector is zero");
        return 0;
    }

    let LDT_BIT = 4;
    let SELECTOR_MASK = 0xfff8;

    if (selector & LDT_BIT) > 0 {
        let ldt = (gdtbase + (ldt as u32 & SELECTOR_MASK)) as *mut SegmentDesc;
        let ldtbase = unsafe { (*ldt).get_base() };

        let segment = (ldtbase + (selector as u32 & SELECTOR_MASK)) as *mut SegmentDesc;
        let segment_base = unsafe { (*segment).get_base() };
        return segment_base;
    } else {
        let segment = (gdtbase + (selector as u32 & SELECTOR_MASK)) as *mut SegmentDesc;
        let segment_base = unsafe { (*segment).get_base() };
        return segment_base;
    }

    println!("no dice :(");
    0
}

pub fn get_vmcs_host_regs() -> VmcsRegs {
    let mut regs = VmcsRegs::new();
    regs.es.sel = read_es();
    regs.cs.sel = read_cs();
    regs.ss.sel = read_ss();
    regs.ds.sel = read_ds();
    regs.fs.sel = read_fs();
    regs.gs.sel = read_gs();
    regs.ldt.sel = read_ldt();
    regs.tr.sel = read_tr();

    /*
    println!("selectors: e: {}, c: {}, s: {}, d: {}, f: {}, g: {}, ldt: {}, tr: {}",
            regs.es.sel, regs.cs.sel, regs.ss.sel, regs.ds.sel,
            regs.fs.sel, regs.gs.sel, regs.ldt.sel, regs.tr.sel);
    */

    regs.cr0 = Cr0::read_raw();
    regs.cr3 = Cr3::read().0.start_address().as_u64();
    regs.cr4 = Cr4::read_raw();

    // println!("cr0: {:#x}, cr3: {:#x}, cr4: {:#x}", regs.cr0, regs.cr3, regs.cr4);

    regs.es.limit = load_segment_limit(regs.es.sel);
    regs.cs.limit = load_segment_limit(regs.cs.sel);
    regs.ss.limit = load_segment_limit(regs.ss.sel);
    regs.ds.limit = load_segment_limit(regs.ds.sel);
    regs.fs.limit = load_segment_limit(regs.fs.sel);
    regs.gs.limit = load_segment_limit(regs.gs.sel);
    regs.ldt.limit = load_segment_limit(regs.ldt.sel);
    regs.tr.limit = load_segment_limit(regs.tr.sel);

    // println!("limits: e: {:#x}, c: {:#x}, s: {:#x}, d: {:#x}, f: {:#x}, g: {:#x}, ldt: {:#x}, tr: {:#x}",
    // regs.es.limit, regs.cs.limit, regs.ss.limit, regs.ds.limit, regs.fs.limit,
    // regs.gs.limit, regs.ldt.limit, regs.tr.limit);

    regs.es.acr = get_segment_access_rights(regs.es.sel);
    regs.cs.acr = get_segment_access_rights(regs.cs.sel);
    regs.ss.acr = get_segment_access_rights(regs.ss.sel);
    regs.ds.acr = get_segment_access_rights(regs.ds.sel);
    regs.fs.acr = get_segment_access_rights(regs.fs.sel);
    regs.gs.acr = get_segment_access_rights(regs.gs.sel);
    regs.ldt.acr = get_segment_access_rights(regs.ldt.sel);
    regs.tr.acr = get_segment_access_rights(regs.tr.sel);

    // println!("acr: e: {:#x}, c: {:#x}, s: {:#x}, d: {:#x}, f: {:#x}, g: {:#x}, ldt: {:#x}, tr: {:#x}",
    //regs.es.acr, regs.cs.acr, regs.ss.acr, regs.ds.acr, regs.fs.acr,
    //regs.gs.acr, regs.ldt.acr, regs.tr.acr);

    let gdt = read_gdt();
    regs.gdtr.base = gdt.base;
    regs.gdtr.limit = gdt.limit;

    // println!("GDT base: {:#x} limit: {:#x}", regs.gdtr.base, regs.gdtr.limit);

    let idt = read_idt();
    regs.idtr.base = idt.base;
    regs.idtr.limit = idt.limit;

    // println!("IDT base: {:#x} limit: {:#x}", regs.idtr.base, regs.idtr.limit);

    regs.es.base = get_segment_base(regs.gdtr.base, regs.ldt.sel, regs.es.sel);
    regs.cs.base = get_segment_base(regs.gdtr.base, regs.ldt.sel, regs.cs.sel);
    regs.ss.base = get_segment_base(regs.gdtr.base, regs.ldt.sel, regs.ss.sel);
    regs.ds.base = get_segment_base(regs.gdtr.base, regs.ldt.sel, regs.ds.sel);
    regs.fs.base = get_segment_base(regs.gdtr.base, regs.ldt.sel, regs.fs.sel);
    regs.gs.base = get_segment_base(regs.gdtr.base, regs.ldt.sel, regs.gs.sel);
    regs.ldt.base = get_segment_base(regs.gdtr.base, regs.ldt.sel, regs.ldt.sel);
    regs.tr.base = get_segment_base(regs.gdtr.base, regs.ldt.sel, regs.tr.sel);

    /*
    println!("Bases: e: {:#x}, c: {:#x}, s: {:#x}, d: {:#x}, f: {:#x}, g: {:#x}, ldt: {:#x}, tr: {:#x}",
        regs.es.base,
        regs.cs.base,
        regs.ss.base,
        regs.ds.base,
        regs.fs.base,
        regs.gs.base,
        regs.ldt.base,
        regs.tr.base,
    );
g   */

    regs.dr7 = read_dr7();
    regs.rflags = read_rflags();
    regs
}
