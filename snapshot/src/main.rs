use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};

const SNAPSHOT_REGS: &str = "SNAPSHOT_regs";

/// Return a u8 slice from a struct
///
/// Example:
/// let vmregs = VmRegs {
///     rax: 0xdeadbeef,
///     ...
/// };
///
/// // Write the snapshot regs file
/// let mut regs_file = File::create(SNAPSHOT_REGS)?;
/// regs_file.write(as_u8_slice(&vmregs))?;
fn as_u8_slice<T: Sized>(data: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((data as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

const XSAVE_AREA_SIZE: usize = 0x340;

#[derive(Clone, Copy, Debug)]
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
    pub rdtsc_low_after: u64 // 26
}

#[derive(Clone, Copy, Debug)]
#[repr(packed, C)]
pub struct VmSelector {
    base: u64,
    limit: u32,
    access_rights: u32,
    sel: u16,
    reserved0: u16,
    reserved1: u32,
}

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
    pub cs_sel: VmSelector,
    pub ds_sel: VmSelector,
    pub es_sel: VmSelector,
    pub fs: VmSelector,
    pub gs: VmSelector,
    pub ss_sel: VmSelector,
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
}

#[derive(Clone, Copy, Debug)]
#[repr(packed, C)]
struct XSaveState {
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
}

#[derive(Clone, Copy, Debug)]
#[repr(packed, C)]
pub struct FxState {
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
}

#[derive(Clone, Copy, Debug)]
#[repr(packed, C)]
pub struct XSaveHeader {
    pub xtate_bv: u64,
    pub xcomp_bc: u64,
    pub reserved_1: u64,
    pub reserved_2: u64,
    pub reserved_3: u64,
    pub reserved_4: u64,
    pub reserved_5: u64,
    pub reserved_6: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(packed, C)]
pub struct OtherRegs {
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
}

/// Return the u64 from memory for given physical address
pub fn get_qword(address: u64, mem_regions: &Vec<&MemRegion>, data: &Vec<u8>) -> u64 {
    if address >= 0xe000_0000 && address < 0x1_0000_0000 {
        // println!("Ignoring address [0xe000_0000..0x1_0000_0000]: {:#x}", address);
        return 0;
    }
    for mem_region in mem_regions {
        let start = mem_region.phys_start;
        let end = mem_region.phys_start + mem_region.length;

        if start <= address && address <= end {
            let data_start = mem_region.data_offset as usize;
            let data_end = (mem_region.data_offset + mem_region.length) as usize;
            // print!("start: {:#x} end: {:#x}\n", data_start, data_end);
            let memory = &data[data_start..data_end];
            // Covert the slice to a u64

            let result = unsafe {
                *(memory[(address - start) as usize..(address - start + 8) as usize].as_ptr()
                    as *const u64)
            };
            return result;
        }
    }

    panic!(format!("Unable to find qword for address: {:#x}", address));
}

/// Returns the virtual addresses and the virt to phys tranlations mapping from
/// the data of a vbox core file
pub fn translate_phys(vaddr: u64, cr3: u64, data: &[u8]) -> usize {
    let cr3 = cr3 & 0xffff_ffff_ffff_f000;
    let mut curr_page = cr3;

    /* Calculate the components for each level of the page table from
     * the vaddr.
     */
    let cr_offsets: [u64; 4] = [
        ((vaddr >> 39) & 0x1ff), /* 512 GiB */
        ((vaddr >> 30) & 0x1ff), /*   1 GiB */
        ((vaddr >> 21) & 0x1ff), /*   2 MiB */
        ((vaddr >> 12) & 0x1ff), /*   4 KiB */
    ];

    /* For each level in the page table */
    for (_depth, curr_offset) in cr_offsets.iter().enumerate() {
        /* Get the page table entry */
        let start_offset = (curr_page + (curr_offset * 8)) as usize;
        let end_offset = (curr_page + (curr_offset * 8) + 8) as usize;
        print!("{:#010x} -> {:#010x} => ", start_offset, end_offset);
        let entry = u64::from_le_bytes(match data.get(start_offset..end_offset) {
            None => return 0,
            Some(x) => x.try_into().unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]),
        });

        /* Get the physical address of the next level */
        curr_page = entry & 0xffff_ffff_f000;
        println!("entry: {:#x}", entry);
    }

    curr_page as usize
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MemRegion {
    major_version: u32,
    minor_version: u32,
    data_offset: u64,
    unused1: u64,
    phys_start: u64,
    unused2: u64,
    length: u64,
    unused3: u64,
}

fn main() -> std::io::Result<()> {
    // The VBCPU data /should/ be within the first 0x2000 bytes of the file
    let mut file = File::open("snapshot.dmp").expect("\nFILE NOT FOUND: snapshot.dmp\n");
    let mut data = [0; 0x2000];
    file.read_exact(&mut data).expect("Unable to read snapshot.dmp file");

    // Find the offset to the start of the VBCPU struct containing guest reg/mem info
    let mut vbcpu_offset = 0;
    loop {
        if data[vbcpu_offset] == 'V' as u8
            && data[vbcpu_offset + 1] == 'B' as u8
            && data[vbcpu_offset + 2] == 'C' as u8
            && data[vbcpu_offset + 3] == 'P' as u8
            && data[vbcpu_offset + 4] == 'U' as u8
        {
            // Skip over the VBCPU bytes themselves
            vbcpu_offset += 8;

            break;
        }

        vbcpu_offset += 1;
    }

    println!("Found vbcpu: {:#x}", vbcpu_offset);

    let vbcpu_len = core::mem::size_of::<Vbcpu>();
    let vbcpu =
        unsafe { &*(data[vbcpu_offset..vbcpu_offset + vbcpu_len].as_ptr() as *const Vbcpu) };
    println!(" ----- SNAPSHOT ----- ");
    unsafe { 
        println!("RIP: {:#x}", vbcpu.rip);
    }
    println!(" ----- SNAPSHOT -----\n\n");

    assert!(XSAVE_AREA_SIZE == vbcpu.cbext as usize);

    // Write the full vbcpu to disk for barberslice
    let mut regs_file = File::create(SNAPSHOT_REGS)?;
    regs_file.write(as_u8_slice(&*vbcpu))?;

    Ok(())
}
