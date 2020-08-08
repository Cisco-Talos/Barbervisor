// extern crate regex;
use regex::Regex;

use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, BufReader, BufRead};

/// Returns the virtual addresses and the virt to phys tranlations mapping from
/// the data of a vbox core file
pub fn translate_phys(vaddr: u64, cr3: u64, data: &[u8]) -> usize {
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
    for (depth, curr_offset) in cr_offsets.iter().enumerate() {
        /* Get the page table entry */
        let start_offset = (curr_page + (curr_offset * 8)) as usize;
        let end_offset = (curr_page + (curr_offset * 8) + 8) as usize;

        let entry = u64::from_le_bytes(data[start_offset..end_offset].try_into().unwrap());

        /* Get the physical address of the next level */
        curr_page = entry & 0xffff_ffff_f000;
        // println!("entry: {:#x}", entry);
    }

    curr_page as usize
}

fn windbg_to_vmregs(input: &str) -> VmRegs {
    // rax=000002ea580f3f70 rbx=0000000000000018 rcx=000002ea580f3f70
    // rdx=000000fa11aef478 rsi=000000fa11aefb30 rdi=000002ea580f3f70
    // rip=00007ffde842275b rsp=000000fa11aef430 rbp=000000fa11aef530
    //  r8=0000000000000002  r9=0000000000000090 r10=000002ea580f3f70
    // r11=000000fa11aef420 r12=000000fa11af06f0 r13=000002ea479b7720
    // r14=0000000000000001 r15=0000000000000000
    // iopl=0         nv up ei pl nz ac po cy
    // cs=0033  ss=002b  ds=002b  es=002b fs=0053  gs=002b             efl=00000217

    let re = Regex::new(
        "...=(?P<rax>[a-f0-9]{16}) ...=(?P<rbx>[a-f0-9]{16}) ...=(?P<rcx>[a-f0-9]{16})\r\n\
         ...=(?P<rdx>[a-f0-9]{16}) ...=(?P<rsi>[a-f0-9]{16}) ...=(?P<rdi>[a-f0-9]{16})\r\n\
         ...=(?P<rip>[a-f0-9]{16}) ...=(?P<rsp>[a-f0-9]{16}) ...=(?P<rbp>[a-f0-9]{16})\r\n\
         ...=(?P<r8>[a-f0-9]{16}) ...=(?P<r9>[a-f0-9]{16}) ...=(?P<r10>[a-f0-9]{16})\r\n\
         ...=(?P<r11>[a-f0-9]{16}) ...=(?P<r12>[a-f0-9]{16}) ...=(?P<r13>[a-f0-9]{16})\r\n\
         ...=(?P<r14>[a-f0-9]{16}) ...=(?P<r15>[a-f0-9]{16})\r\n\
         .*?\r\n\
         cs.*efl=(?P<rflags>.*)\r\n",
    )
    .unwrap();

    let m = re.captures(&input).expect("Unable to capture");
    let mut vbox = VmRegs {
        rax: u64::from_str_radix(m.name("rax").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        rcx: u64::from_str_radix(m.name("rcx").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        rdx: u64::from_str_radix(m.name("rdx").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        rbx: u64::from_str_radix(m.name("rbx").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        cr2: 0,
        rbp: u64::from_str_radix(m.name("rbp").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        rsi: u64::from_str_radix(m.name("rsi").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        rdi: u64::from_str_radix(m.name("rdi").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        r8: u64::from_str_radix(m.name("r8").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        r9: u64::from_str_radix(m.name("r9").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        r10: u64::from_str_radix(m.name("r10").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        r11: u64::from_str_radix(m.name("r11").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        r12: u64::from_str_radix(m.name("r12").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        r13: u64::from_str_radix(m.name("r13").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        r14: u64::from_str_radix(m.name("r14").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        r15: u64::from_str_radix(m.name("r15").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        rsp: u64::from_str_radix(m.name("rsp").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        rip: u64::from_str_radix(m.name("rip").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        rflags: u64::from_str_radix(m.name("rflags").unwrap().as_str(), 16)
            .ok()
            .unwrap(),
        gs_base: 0,
        kernel_gs_base: 0,
        guest_xsave_area_addr: 0,
        host_xsave_area_addr: 0,
        rdtsc_high_before: 0, // 23
        rdtsc_low_before: 0, // 24
        rdtsc_high_after: 0, // 25
        rdtsc_low_after: 0 // 26
    };

    vbox
}

fn vbox() -> std::io::Result<()> {
    /* Open barberslice trace */
    let mut orig_trace = File::open("../tftp-server/test.trace")?;

    let mut buffer = [0; std::mem::size_of::<VmRegs>()];
    for i in 0..824133 {
        orig_trace.read_exact(&mut buffer);
    }

    /* Open vbox-windbg trace */
    let mut vbox = File::open("windbg_trace.txt")?;
    let mut reader = BufReader::new(vbox);

    // Ignore these 2 opening lines:
    //   Opened log file 'windbg_trace.txt'
    //   0:000> r; t; z(@rip != 0x7ff77393b375)
    let mut lines = reader.lines().skip(2 + 11);
    let mut single_step = String::new();
    let mut counter = 0;

    loop {
        // Read next instruction from vbox
        single_step.clear();
        for i in 0..11 {
            single_step += &lines.next().unwrap().unwrap();
            single_step += "\r\n";
        }
        let mut vbox = windbg_to_vmregs(&single_step);

        let mut kernel = false;

        let mut data;
        let mut counter = 0;
        loop {
            let mut buffer = [0; std::mem::size_of::<VmRegs>()];
            orig_trace.read_exact(&mut buffer);
            data = unsafe { *(buffer.as_ptr() as *const VmRegs) };
            if data.rip >> 63 & 1 == 1 {
                // print!("Skipping: {:#x}\n", data.rip);
                counter += 1;
                continue;
            }
            /*
            if data.rip != vbox.rip {
                // print!("Skipping: {:#x}\n", data.rip);
                continue;
            }
            */
            break;
        }

        print!("SKIPPED {}\n", counter);

        data.gs_base = 0;
        data.kernel_gs_base = 0;
        data.cr2 = 0;
        data.guest_xsave_area_addr = 0;
        data.host_xsave_area_addr = 0;
        vbox.guest_xsave_area_addr = 0;
        vbox.host_xsave_area_addr = 0;

        data.rdtsc_high_before = 0;
        data.rdtsc_low_before = 0;
        data.rdtsc_high_after = 0;
        data.rdtsc_low_after = 0;
        vbox.rdtsc_high_before = 0;
        vbox.rdtsc_low_before = 0;
        vbox.rdtsc_high_after = 0;
        vbox.rdtsc_low_after = 0;

        if vbox.r11 == 0x346 {
            // Ignore collisions based on the TRAP flag enabled in RFLAGS in VBOX since we are
            // single stepping
            vbox.r11 == 0x246;
        }

        // let vbox: VmRegs = unsafe { *(single_step.as_ptr() as *const VmRegs) };
        counter += 1;

        if counter % 10000 == 0 {
            print!("{}\n", counter);
        }

        print!("barbervisor: {:#x} vbox: {:#x}\n\n", data.rip, vbox.rip);
        // if data != vbox {
        if data.rip != vbox.rip {
            println!("barbervisor:");
            data.print();
            println!("");
            println!("vbox:");
            vbox.print();

            println!("DIFF: ");
            if data.rax != vbox.rax {
                print!("rax ");
            }
            if data.rbx != vbox.rbx {
                print!("rbx ");
            }
            if data.rcx != vbox.rcx {
                print!("rcx ");
            }
            if data.rdx != vbox.rdx {
                print!("rdx ");
            }
            if data.rsi != vbox.rsi {
                print!("rsi ");
            }
            if data.rdi != vbox.rdi {
                print!("rdi ");
            }
            if data.r8 != vbox.r8 {
                print!("r8 ");
            }
            if data.r9 != vbox.r9 {
                print!("r9 ");
            }
            if data.r10 != vbox.r10 {
                print!("r10 ");
            }
            if data.r11 != vbox.r11 {
                print!("r11 ");
            }
            if data.r12 != vbox.r12 {
                print!("r12 ");
            }
            if data.r13 != vbox.r13 {
                print!("r13 ");
            }
            if data.r14 != vbox.r14 {
                print!("r14 ");
            }
            if data.r15 != vbox.r15 {
                print!("r15 ");
            }
            if data.rbp != vbox.rbp {
                print!("rbp ");
            }
            if data.rsp != vbox.rsp {
                print!("rsp ");
            }
            if data.rip != vbox.rip {
                print!("rip ");
            }
            if data.rflags != vbox.rflags {
                print!("rflags ");
            }
            if data.gs_base != vbox.gs_base {
                print!("gs_base ");
            }
            if data.kernel_gs_base != vbox.kernel_gs_base {
                print!("kernel_gs_base ");
            }
            if data.cr2 != vbox.cr2 {
                print!("cr2 ");
            }
            println!("\n");
            panic!("COLLISION");
        }
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    vbox() 
}

#[derive(Clone, Copy, Debug)]
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
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(packed, C)]
pub struct VmRegs {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub cr2: u64,
    pub rbp: u64,
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
    pub rsp: u64,

    /// Rip is explicitly not public as we want to gate setting RIP in order to
    /// force the setting of RIP to also be written back to the Guest VMCS
    /// via fuzzvm.set_rip()
    rip: u64,

    pub rflags: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub guest_xsave_area_addr: u64,
    pub host_xsave_area_addr: u64,
    pub rdtsc_high_before: u64, // 23
    pub rdtsc_low_before: u64, // 24
    pub rdtsc_high_after: u64, // 25
    pub rdtsc_low_after: u64 // 26
}

impl VmRegs {
    pub fn from_bytes(bytes: &[u8]) -> VmRegs {
        unsafe { *(bytes.as_ptr() as *const VmRegs) }
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

            print!("rflags: {:#x}\n", self.rflags);
            print!(
                "gs_base: {:#x} k_gs_base: {:#x}\n",
                self.gs_base, self.kernel_gs_base
            );
        }
    }
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
