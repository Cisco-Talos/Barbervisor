pub mod memreader;
pub mod windows;

use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::collections::{HashSet, HashMap};

use crate::memreader::{MemReader, Address};
use crate::windows::*;

/// Get a HashMap of the current user modules key'd by their address range with 
/// value of their base_dll
fn get_user_modules<R: MemReader>(gs_base: u64, cr3: u64, phys_file: &mut R) 
    -> HashMap<Range<u64>, String> {
    let teb = TEB::from_memreader(Address::Virtual(gs_base, cr3), phys_file);
    let peb = PEB::from_memreader(Address::Virtual(teb.process_environment_block, cr3), 
                                  phys_file);
    let ldr = LdrData::from_memreader(Address::Virtual(peb.ldr, cr3), phys_file);

    let mut curr_module = ldr.in_load_order_module_list.flink;
    let mut user_modules = HashMap::new();
    let mut seen_user_modules = HashSet::new();

    while curr_module != 0 {
        // Get the current Ldr Entry
        let ldr_data_entry = LdrDataTableEntry::from_memreader(
            Address::Virtual(curr_module, cr3), phys_file);

        // If we have seen this entry already, break
        if !seen_user_modules.insert(ldr_data_entry.base_name_hash_value) {
            break;
        }

        // Only if the base_dll is properly read from memory do we add it
        let base_dll = ldr_data_entry.base_dll(cr3, phys_file);
        if base_dll.is_some() {
            user_modules.insert(
                ldr_data_entry.dll_base..ldr_data_entry.dll_base+ldr_data_entry.size_of_image,
                base_dll.unwrap());
        }

        curr_module = ldr_data_entry.in_load_order_module_list.flink;
    }

    user_modules
}

fn get_kernel_cr3<R: MemReader>(reader: &mut R) -> Option<u64> {
    // From Volatility3's documentation (DTB - Directory Table Base aka Kernel cr3)
    //
    // New versions of windows, with randomized self-referential pointers, appear to 
    // always load their dtb within a small specific range (`0x1a0000` and `0x1b0000`), 
    // so instead we scan for all self-referential pointers in that range, and ignore any 
    // that contain multiple self-references (since the DTB is very unlikely to point to 
    // itself more than once).
    for counter in (0x1a0000..0x1b0000).step_by(0x1000) {
        for i in (0..0x1000).step_by(8) {
            let curr_ptr = reader.read_u64(
                Address::Physical(counter + i)) & 0xffff_ffff_f000;
            if curr_ptr == counter {
                print!("DTB (kernel_cr3) [{:#x}]: {:#x}\n", counter + i as u64, counter);
                return Some(counter);
            }
        }
    }

    return None;
}

/// Given a physical memory, retrieve the kernel modules currently loaded. 
///
/// The `user_modules_hash` number is a number used to cache some of values needed to find the kernel 
/// modules. These values can take some time to find (10 - 20 seconds), so we cache them in a small `cache/` 
/// directory to save effort.
fn get_kernel_modules<R: MemReader>(reader: &mut R, user_modules_hash: u64) 
    -> HashMap<Range<u64>, String> {
    let mut buffer = [0u8; 0x1000];
    let needle = "\\SystemRoot\\system32\\nt";
    let needle: Vec<u8> = needle.bytes().collect();
    let needle_len = needle.len();
    let kernel_cr3 = get_kernel_cr3(reader).expect("Unable to get kernel cr3");
    print!("KCR3: {:x?}\n", kernel_cr3);

    // Retrieve the KDBG from the cache file or the MemReader
    let kdbg_file = format!("../parse_trace/cache/{:#x}.kdbg", user_modules_hash);
    let kdbg = match File::open(&kdbg_file) {
        Ok(mut file) => {
            let mut buffer = [0; 8];
            file.read_exact(&mut buffer).expect("Unable to read kdbg");
            u64::from_le_bytes(buffer)
        }
        Err(_) => {
            let kdbg;
            let mut counter = 0;
            'leave: loop {
                reader.read_mem(Address::Physical(counter), &mut buffer)
                      .expect(&format!("Unable to read addr looking for KDBG: {:#x}", counter));
                for i in 0..0x1000-needle_len {
                    if &buffer[i..i+needle_len] == needle.as_slice() {
                        for back_offset in 0..0x40 {
                            // let check_addr = (counter + i as u64).saturating_sub(0x18);
                            let check_addr = (counter + i as u64).saturating_sub(back_offset);
                            let possible_kdbg = reader.read_u64(Address::Physical(check_addr)) 
                                & 0xffff_ffff_ffff;
                            let mut fileheader = [0; 2];
                            let res = reader.read_mem(Address::Virtual(possible_kdbg, kernel_cr3), 
                                                    &mut fileheader);
                            if res.is_err() { continue; }
                            if fileheader == ['M' as u8, 'Z' as u8] {
                                print!("KDBG [{:#x}]: {:#x}\n", counter + i as u64, possible_kdbg);
                                kdbg = possible_kdbg;
                                let mut file = File::create(kdbg_file).expect("Unable to create KDBG cache");
                                file.write_all(&kdbg.to_le_bytes()).expect("Unable to write kdbg");
                                break 'leave;
                            }
                        }
                    }
                }
                counter += 0x1000;
            }
            kdbg
        }
    };

    print!("KDBG: {:x?}\n", kdbg);
    let plml_file = format!("../parse_trace/cache/{:#x}.plml", user_modules_hash);
    let psloadedmodulelist_offset = match File::open(&plml_file) {
        Ok(mut file) => {
            let mut buffer = [0; 8];
            file.read_exact(&mut buffer).expect("Unable to read plml");
            u64::from_le_bytes(buffer)
        }
        Err(_) => {
            // Attempt to brute force the offset of PsLoadedModuleList rather than
            // downloading the PDB for this ntoskrnl.exe and using that
            let mut psloadedmodulelist_offset = 0;
            for offset in (0x0..0x1_0000_0000).step_by(4) {
                let psloadedmodulelist = kdbg + offset;
                let psloadedmodulelist_phys = reader.translate(
                    Address::Virtual(psloadedmodulelist, kernel_cr3));

                // If translate_phys was null, continue to look
                if psloadedmodulelist_phys.is_none() { continue; }
            
                // Guarenteed to be some now
                let psloadedmodulelist_phys = psloadedmodulelist_phys.unwrap() as u64;

                // print!("_phys {:#x}\n", psloadedmodulelist_phys);
                let ldr_data_table_entry = reader.read_u64( 
                    Address::Physical(psloadedmodulelist_phys)) & 0xffff_ffff_ffff;
                let ldr_data_table_entry_phys = reader.translate(
                    Address::Virtual(ldr_data_table_entry, kernel_cr3));

                // If translate_phys was null, continue to look
                if ldr_data_table_entry_phys.is_none() { continue; }

                // Guarenteed to be some now
                let ldr_data_table_entry_phys = ldr_data_table_entry_phys.unwrap() as u64;

                if ldr_data_table_entry_phys == 0xe0000000 {
                    continue;
                }

                // print!("{:#x}\n", ldr_data_table_entry_phys);
                let data_entry = KldrDataTableEntry::from_memreader(
                    Address::Physical(ldr_data_table_entry_phys), reader);

                if data_entry.flink >> 63 == 0 { continue; }
                if data_entry.blink >> 63 == 0 { continue; }

                let curr_base = data_entry.base_dll(kernel_cr3, reader);
                if curr_base.is_none() { continue; }

                // If the first dll is ntoskrnl.exe, we assume we have found the right offset
                if "ntoskrnl.exe" == curr_base.unwrap() {
                    print!("Found PsLoadedModuleList: {:#x}\n", offset);
                    psloadedmodulelist_offset = offset;
                    let mut file = File::create(plml_file).expect("Unable to create PLML");
                    file.write_all(&offset.to_le_bytes()).expect("Unable to write PLML");
                    break;
                }
            }
            psloadedmodulelist_offset
        }
    };

    assert!(psloadedmodulelist_offset > 0, "Failed to find PsLoadedModuleList offset");
    print!("PLML offset: {:x?}\n", psloadedmodulelist_offset);

    let mut psloadedmodulelist = kdbg + psloadedmodulelist_offset;
    let mut found = HashSet::new();
    let mut kernel_modules = HashMap::new();

    loop {
        let psloadedmodulelist_phys = reader.translate(
            Address::Virtual(psloadedmodulelist, kernel_cr3)).unwrap() as u64;
        let data_entry = KldrDataTableEntry::from_memreader(
            Address::Physical(psloadedmodulelist_phys), reader);

        // Set the next loop address in case we can't resolve the base dll or full dll
        psloadedmodulelist = data_entry.flink;
        let base_dll = match data_entry.base_dll(kernel_cr3, reader) {
            None => continue,
            Some(dll) => dll
        };

        let _full_dll = match data_entry.full_dll(kernel_cr3, reader) {
            None => continue,
            Some(dll) => dll
        };

        let dll_base = data_entry.dll_base;
        let size = data_entry.size_of_image;
        kernel_modules.insert(dll_base..dll_base+size, base_dll.to_string());

        if !found.insert(base_dll) {
            break;
        }
    }

    kernel_modules
}

fn main() -> std::io::Result<()> {
    let mut phys_file = File::open("../snapshot/snapshot.phys").expect("FILE NOT FOUND: snapshot.phys");

    let mut file = File::open("../snapshot/SNAPSHOT_regs").expect("FILE NOT FOUND: snapshot_regs");
    let mut regs_data = Vec::new();
    file.read_to_end(&mut regs_data).expect("Unable to read snapshot regs file");

    let vbcpu = unsafe { &*(regs_data.as_ptr() as *const Vbcpu) };

    let cr3 = vbcpu.cr3 & 0xffff_ffff_ffff_f000;
    let gs_base = vbcpu.gs.base;
    let mut user_modules = get_user_modules(gs_base, cr3, &mut phys_file);
    print!("{:#x?}\n", user_modules);

    // Generate a stupid simple "hash" for the user modules to cache the kernel information
    // that takes a while to process (5 - 10 seconds)
    let mut user_modules_hash: u64 = 0;
    for (k, _v) in &user_modules {
        user_modules_hash = user_modules_hash.wrapping_add(k.start);
        user_modules_hash = user_modules_hash.wrapping_add(k.end);
    }
    print!("User modules hash: {:#x}\n", user_modules_hash);
    let cr3_file = format!("../parse_trace/cache/{:#x}.cr3", user_modules_hash);
    let kernel_cr3 = match File::open(&cr3_file) {
        Ok(mut file) => {
            let mut buffer = [0; 8];
            file.read_exact(&mut buffer).expect("Unable to read cr3");
            u64::from_le_bytes(buffer)
        }
        Err(_) => {
            let kernel_cr3 = get_kernel_cr3(&mut phys_file).expect("Unable to get kernel_cr3");
            let mut file = File::create(cr3_file)?;
            file.write_all(&kernel_cr3.to_le_bytes());
            kernel_cr3
        }
    };

    print!("Kernel cr3: {:#x}\n", kernel_cr3);

    // Get the kernel modules from the snapshot
    let kernel_modules = get_kernel_modules(&mut phys_file, user_modules_hash);
    print!("{:#x?}\n", kernel_modules);
    for (r, module) in kernel_modules.iter() {
        if module == "ntoskrnl.exe" {
            print!("{:x?} {}\n", r, module);
            break;
        }
    }

    // Read the coverage file from the hypervisor
    let mut file = File::open("../tftp-server/coverage.txt")?;
    let mut addrs = Vec::new();
    loop {
        let mut data = [0u8; 8];
        let res = file.read_exact(&mut data).expect("Unable to read coverage.txt");
        if res.is_err() {
            break;
        }
        let addr = u64::from_le_bytes(data);
        addrs.push(addr);
    }

    // Combine the user modules and kernel modules into one HashMap
    let mut all_modules = kernel_modules;
    for (k, v) in user_modules.iter() {
        all_modules.insert(k.clone(), v.to_string());
    }

    // Create the module+offset format for lighthouse for each found address
    let mut res = Vec::new();
    'top: for addr in addrs {
        print!("{:#x}\n", addr);
        for (check, module) in all_modules.iter() {
            if check.contains(&addr) {
                res.push(format!("{}+{:x}", module, addr - check.start));
                continue 'top;
            }
        }

    }

    // Create the lighthouse file
    let mut lighthouse = File::create(format!("lighthouse-{:?}.txt", 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)))?;

    // Write the lighthouse file in sorted order
    res.sort();
    for x in res {
        lighthouse.write(format!("{}\n", x).as_bytes());
    }

    Ok(())
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
