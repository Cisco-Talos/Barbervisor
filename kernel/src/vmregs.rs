//! Register structures used to pass registers from the server to the hypervisor
use crate::{print, vga_print};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(packed, C)]
pub struct VmRegs {
    pub rax: u64, // 0
    pub rcx: u64, // 1
    pub rdx: u64, // 2
    pub rbx: u64, // 3
    pub cr2: u64, // 4
    pub rbp: u64, // 5
    pub rsi: u64, // 6
    pub rdi: u64, // 7
    pub r8: u64,  // 8
    pub r9: u64, // 9
    pub r10: u64, // 10
    pub r11: u64, // 11
    pub r12: u64, // 12
    pub r13: u64, // 13
    pub r14: u64, // 14
    pub r15: u64, // 15
    pub rsp: u64, // 16

    /// Rip is explicitly not public as we want to gate setting RIP in order to
    /// force the setting of RIP to also be written back to the Guest VMCS
    /// via fuzzvm.set_rip()
    rip: u64, // 17

    pub rflags: u64, // 18
    pub gs_base: u64, // 19
    pub kernel_gs_base: u64, // 20
    pub guest_xsave_area_addr: u64, // 21
    pub host_xsave_area_addr: u64, // 22
    pub rdtsc_high_before: u64, // 23
    pub rdtsc_low_before: u64, // 24
    pub rdtsc_high_after: u64, // 25
    pub rdtsc_low_after: u64, // 26
    pub retired_instructions_high: u64, // 27
    pub retired_instructions_low: u64, // 28
    pub cr8: u64 // 29
}

impl VmRegs {
    pub fn from_bytes(bytes: &[u8]) -> VmRegs {
        unsafe { *(bytes.as_ptr() as *const VmRegs) }
    }

    pub fn from_vbcpu(vbcpu: &Vbcpu) -> VmRegs {
        VmRegs {
            rax: vbcpu.rax,
            rcx: vbcpu.rcx,
            rdx: vbcpu.rdx,
            rbx: vbcpu.rbx,
            cr2: vbcpu.cr2,
            rbp: vbcpu.rbp,
            rsi: vbcpu.rsi,
            rdi: vbcpu.rdi,
            r8: vbcpu.r8,
            r9: vbcpu.r9,
            r10: vbcpu.r10,
            r11: vbcpu.r11,
            r12: vbcpu.r12,
            r13: vbcpu.r13,
            r14: vbcpu.r14,
            r15: vbcpu.r15,
            rsp: vbcpu.rsp,
            rip: vbcpu.rip,
            rflags: vbcpu.rflags,
            gs_base: vbcpu.gs.base,
            kernel_gs_base: vbcpu.msr_kernel_gs_base,
            guest_xsave_area_addr: 0,
            host_xsave_area_addr: 0,
            rdtsc_high_before: 0, // 23
            rdtsc_low_before: 0, // 24
            rdtsc_high_after: 0, // 25
            rdtsc_low_after: 0, // 26
            retired_instructions_high: 0, // 27
            retired_instructions_low: 0, // 28
            cr8: 0, // 29
        }
    }

    pub fn print(&self) {
        unsafe {
            print!(
                "rax: {:<#18x} rbx: {:<#18x} rcx: {:<#18x}\n",
                self.rax, self.rbx, self.rcx
            );
            print!(
                "rdx: {:<#18x} rsi: {:<#18x} rdi: {:<#18x}\n",
                self.rdx, self.rsi, self.rdi
            );
            print!(
                "r8 : {:<#18x} r9 : {:<#18x} r10: {:<#18x}\n",
                self.r8, self.r9, self.r10
            );
            print!(
                "r11: {:<#18x} r12: {:<#18x} r13: {:<#18x}\n",
                self.r11, self.r12, self.r13
            );
            print!(
                "r14: {:<#18x} r15: {:<#18x} rsp: {:<#18x}\n",
                self.r14, self.r15, self.rsp
            );
            print!(
                "rbp: {:<#18x} rip: {:<#18x} cr2: {:<#18x}\n",
                self.rbp, self.rip, self.cr2
            );
            print!("rflags: {:?}\n", RFlags::from_bits_truncate(self.rflags));
            print!(
                "gs_base: {:<#18x} kernel_gs_base: {:<#18x}\n",
                self.gs_base, self.kernel_gs_base
            );
        }
    }

    pub(super) fn get_rip(&self) -> u64 {
        self.rip
    }

    pub(super) fn set_rip(&mut self, rip: u64) {
        self.rip = rip;
    }

    pub fn vga_print(&self) {
        unsafe {
            vga_print!(
                "rax: {:<#18x} rbx: {:<#18x} rcx: {:<#18x}\n",
                self.rax,
                self.rbx,
                self.rcx
            );
            vga_print!(
                "rdx: {:<#18x} rsi: {:<#18x} rdi: {:<#18x}\n",
                self.rdx,
                self.rsi,
                self.rdi
            );
            vga_print!(
                "r8 : {:<#18x} r9 : {:<#18x} r10: {:<#18x}\n",
                self.r8,
                self.r9,
                self.r10
            );
            vga_print!(
                "r11: {:<#18x} r12: {:<#18x} r13: {:<#18x}\n",
                self.r11,
                self.r12,
                self.r13
            );
            vga_print!(
                "r14: {:<#18x} r15: {:<#18x} rsp: {:<#18x}\n",
                self.r14,
                self.r15,
                self.rsp
            );
            vga_print!(
                "rbp: {:<#18x} rip: {:<#18x} cr2: {:<#18x}\n",
                self.rbp,
                self.rip,
                self.cr2
            );
            vga_print!("rflags: {:?}\n", RFlags::from_bits_truncate(self.rflags));
            vga_print!(
                "gs_base: {:<#18x} kernel_gs_base: {:<#18x}\n",
                self.gs_base,
                self.kernel_gs_base
            );
        }
    }
}

bitflags! {
    pub struct RFlags: u64 {
        const CARRY = 1 << 0;
        const PARITY = 1 << 2;
        const ADJUST = 1 << 4;
        const ZERO = 1 << 6;
        const SIGN = 1 << 7;
        const TRAP = 1 << 8;
        const INTERRUPT_ENABLE = 1 << 9;
        const DIRECTION = 1 << 10;
        const OVERFLOW = 1 << 11;
        const RESUME = 1 << 16;
        const VIRTUAL8086 = 1 << 17;
        const ALIGNMENT_CHECK = 1 << 18;
        const VIRTUAL_INTERRUPT = 1 << 19;
        const VIRTUAL_INTERRUPT_PENDING = 1 << 20;
        const CAN_USE_CPUID = 1 << 21;
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(packed, C)]
/// Struct describing the selector field from Virtualbox core file
pub struct VmSelector {
    pub base: u64,
    pub limit: u32,
    pub access_rights: u32,
    pub sel: u16,
    pub reserved0: u16,
    pub reserved1: u32,
}

#[derive(Clone, Copy)]
#[repr(packed, C)]
/// Struct used to for receiving the snapshot register data from TFTP
pub struct SnapshotVmRegs {
    pub regs: VmRegs,
    pub cpu: Vbcpu,
}

pub const XSAVE_AREA_SIZE: usize = 0x340;

// https://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/dbgfcorefmt.h
#[derive(Clone, Copy)]
#[repr(packed, C)]
pub struct Vbcpu {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rflags: u64,
    pub cs: VmSelector,
    pub ds: VmSelector,
    pub es: VmSelector,
    pub fs: VmSelector,
    pub gs: VmSelector,
    pub ss: VmSelector,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr4: u64,
    pub dr5: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub gdtr_addr: u64,
    pub gdtr_cb: u32,
    pub gdtr_reserved: u32,
    pub idtr_addr: u64,
    pub idtr_cb: u32,
    pub idtr_reserved: u32,
    pub ldtr: VmSelector,
    pub tr: VmSelector,
    pub sysenter_cs: u64,
    pub sysenter_eip: u64,
    pub sysenter_esp: u64,
    pub msr_efer: u64,
    pub msr_star: u64,
    pub msr_pat: u64,
    pub msr_lstar: u64,
    pub msr_cstar: u64,
    pub msr_sfmask: u64,
    pub msr_kernel_gs_base: u64,
    pub msr_apic_base: u64,
    pub xcr0: u64,
    pub xcr1: u64,
    pub cbext: u32,
    pub padding0: u32,
    pub xsave_state: [u8; XSAVE_AREA_SIZE]

    /*
    pub control: u16,
    pub status: u16,
    pub tag: u16,
    pub opcode: u16,
    pub instruction_pointer: u32,
    pub code_selector: u16,
    pub reserved_1: u16,
    pub data_pointer: u32,
    pub data_segment: u16,
    pub reserved_2: u16,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub st0: u128,
    pub st1: u128,
    pub st2: u128,
    pub st3: u128,
    pub st4: u128,
    pub st5: u128,
    pub st6: u128,
    pub st7: u128,
    pub xmm0: u128,
    pub xmm1: u128,
    pub xmm2: u128,
    pub xmm3: u128,
    pub xmm4: u128,
    pub xmm5: u128,
    pub xmm6: u128,
    pub xmm7: u128,
    pub xmm8: u128,
    pub xmm9: u128,
    pub xmm10: u128,
    pub xmm11: u128,
    pub xmm12: u128,
    pub xmm13: u128,
    pub xmm14: u128,
    pub xmm15: u128,
    pub reserved_for_software1: u128,
    pub reserved_for_software2: u128,
    pub reserved_for_software3: u128,
    pub xsave_header: XSaveHeader,
    pub ymm0: u128,
    pub ymm1: u128,
    pub ymm2: u128,
    pub ymm3: u128,
    pub ymm4: u128,
    pub ymm5: u128,
    pub ymm6: u128,
    pub ymm7: u128,
    pub ymm8: u128,
    pub ymm9: u128,
    pub ymm10: u128,
    pub ymm11: u128,
    pub ymm12: u128,
    pub ymm13: u128,
    pub ymm14: u128,
    pub ymm15: u128,
    pub bnd0: u128,
    pub bnd1: u128,
    pub bnd2: u128,
    pub bnd3: u128,
    pub bnd_config: u64,
    pub bnd_status: u64,
    pub reserved_to_match_docs0: u128,
    pub reserved_to_match_docs1: u128,
    pub reserved_to_match_docs2: u128,
    pub reserved_to_match_docs3: u128,
    pub reserved_to_match_docs4: u128,
    pub reserved_to_match_docs5: u128,
    pub reserved_to_match_docs6: u128,
    pub reserved_to_match_docs7: u128,
    pub reserved_to_match_docs8: u128,
    pub reserved_to_match_docs9: u128,
    pub reserved_to_match_docs10: u128,
    pub reserved_to_match_docs11: u128,
    pub reserved_to_match_docs12: u128,
    pub reserved_to_match_docs13: u128,
    pub reserved_to_match_docs14: u128,
    pub reserved_to_match_docs15: u128,
    pub k0: u64,
    pub k1: u64,
    pub k2: u64,
    pub k3: u64,
    pub k4: u64,
    pub k5: u64,
    pub k6: u64,
    pub k7: u64,
    pub zmm0: [u128; 2],
    pub zmm1: [u128; 2],
    pub zmm2: [u128; 2],
    pub zmm3: [u128; 2],
    pub zmm4: [u128; 2],
    pub zmm5: [u128; 2],
    pub zmm6: [u128; 2],
    pub zmm7: [u128; 2],
    pub zmm8: [u128; 2],
    pub zmm9: [u128; 2],
    pub zmm10: [u128; 2],
    pub zmm11: [u128; 2],
    pub zmm12: [u128; 2],
    pub zmm13: [u128; 2],
    pub zmm14: [u128; 2],
    pub zmm15: [u128; 2],
    pub zmm16: [u128; 4],
    pub zmm17: [u128; 4],
    pub zmm18: [u128; 4],
    pub zmm19: [u128; 4],
    pub zmm20: [u128; 4],
    pub zmm21: [u128; 4],
    pub zmm22: [u128; 4],
    pub zmm23: [u128; 4],
    pub zmm24: [u128; 4],
    pub zmm25: [u128; 4],
    pub zmm26: [u128; 4],
    pub zmm27: [u128; 4],
    pub zmm28: [u128; 4],
    pub zmm29: [u128; 4],
    pub zmm30: [u128; 4],
    pub zmm31: [u128; 4],
    */
}

#[derive(Clone, Copy, Debug)]
#[repr(packed, C)]
pub struct XSaveHeader {
    pub xtate_bv: u64, pub xcomp_bc: u64,
    pub reserved_1: u64, pub reserved_2: u64,
    pub reserved_3: u64, pub reserved_4: u64,
    pub reserved_5: u64, pub reserved_6: u64,

}
