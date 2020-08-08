extern crate capstone;
extern crate pdb;
use capstone::prelude::*;

#[macro_use]
extern crate bitflags;

pub mod memreader;
pub mod windows;

use crate::pdb::FallibleIterator;
use crate::memreader::{MemReader, Address};
use crate::windows::*;
use std::collections::{HashSet, HashMap};

use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;

/// Get a HashMap of the current user modules key'd by their address range with 
/// value of their base_dll
fn get_user_modules<R: MemReader>(gs_base: u64, cr3: u64, phys_file: &mut R) 
    -> HashMap<Range<u64>, String> {
    let teb = TEB::from_memreader(Address::Virtual(gs_base, cr3), phys_file);
    print!("TEB PEB: {:#x}\n", teb.process_environment_block);
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

    let mut found = HashSet::new();
    let mut kernel_modules = HashMap::new();

    // Retrieve the KDBG from the cache file or the MemReader
    let kdbg_file = format!("cache/{:#x}.kdbg", user_modules_hash);
    let kdbg = match File::open(&kdbg_file) {
        Ok(mut file) => {
            let mut buffer = [0; 8];
            file.read_exact(&mut buffer);
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
                                file.write_all(&kdbg.to_le_bytes());
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
    let plml_file = format!("cache/{:#x}.plml", user_modules_hash);
    let psloadedmodulelist_offset = match File::open(&plml_file) {
        Ok(mut file) => {
            let mut buffer = [0; 8];
            file.read_exact(&mut buffer);
            u64::from_le_bytes(buffer)
        }
        Err(_) => {
            // Attempt to brute force the offset of PsLoadedModuleList rather than
            // downloading the PDB for this ntoskrnl.exe and using that
            let mut psloadedmodulelist_offset = 0;
            for offset in (0x0..0x1000_0000).step_by(8) {
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

                let data_entry = KldrDataTableEntry::from_memreader(
                    Address::Physical(ldr_data_table_entry_phys), reader);

                if data_entry.flink >> 63 == 0 { continue; }
                if data_entry.blink >> 63 == 0 { continue; }

                let curr_base = data_entry.base_dll(kernel_cr3, reader);
                if curr_base.is_none() { continue; }

                // If the first dll is ntoskrnl.exe, we assume we have found the right offset
                if "ntoskrnl.exe" == curr_base.unwrap() {
                    print!("Found PsLoadedModuleList: {:#x}\n", offset);
                    print!("ntoskrnl.exe - {}\n", data_entry.size_of_image);
                    let dll_base = data_entry.dll_base;
                    let size = data_entry.size_of_image;
                    kernel_modules.insert(dll_base..dll_base+size, "ntoskrnl.exe".to_string());
                    psloadedmodulelist_offset = offset;
                    let mut file = File::create(plml_file).expect("Unable to create KDBG cache");
                    file.write_all(&offset.to_le_bytes());
                    break;
                }
            }
            psloadedmodulelist_offset
        }
    };

    assert!(psloadedmodulelist_offset > 0, "Failed to find PsLoadedModuleList offset");
    print!("PLML offset: {:x?}\n", psloadedmodulelist_offset);

    // Init ntoskrnl in the kernel_modules
    let mut psloadedmodulelist = kdbg + psloadedmodulelist_offset;
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

        let dll_base = data_entry.dll_base;
        let size = data_entry.size_of_image;
        kernel_modules.insert(dll_base..dll_base+size, base_dll.to_string());

        if !found.insert(base_dll) {
            break;
        }
    }

    kernel_modules
}

fn get_pdb_symbols(pdb_file: &File) -> Vec<(u32, String)> {
    let mut pdb = pdb::PDB::open(pdb_file).expect("Unable to get pdb");

    let symbol_table = pdb.global_symbols().expect("Unable to get symbol table");
    let address_map = pdb.address_map().expect("Unable to get addr map");

    let mut symbols = symbol_table.iter();
    let mut curr_symbols = Vec::new();
    let mut counter = 0;
    loop {
        if let Ok(Some(symbol)) = symbols.next() {
            match symbol.parse() {
                Ok(pdb::SymbolData::PublicSymbol(data)) if data.function => {
                    // we found the location of a function!
                    let rva = data.offset.to_rva(&address_map).unwrap_or_default();
                    curr_symbols.push((rva.0,
                                       symbol.name().expect("No symbol name").to_string().into_owned()));
                    counter = 0;
                }
                _ => { 
                }
            }
        }
        counter += 1;
        // Some silly high number of misses in order to tell when to stop looping
        if counter > 2000 {
            return curr_symbols;
        }
    }
}

/// Internal function to split a virtual address and size into the corresponding physical
/// pages and their size for reading and writing
///
/// Virtual addresses that reach beyond one page will not necessarily be contiguous
/// physical pages in the kernel. For this reason, we need to split reads/writes based on
/// page boundaries, so we precalculate the addresses needed to read/write from and the 
/// sizes to read/write from those addresses. An example is below
///
/// Virtual Address: 0x233fced8550 Read size: 0x33de
///     Addr           Sizes
///     0x233fced8550  0xab0
///     0x233fced9000  0x1000
///     0x233fceda000  0x1000
///     0x233fcedb000  0x92e
///
/// After precalculating these addresses, we translate the virtual address for the 
/// physical address, and then read/write the calculated size, so that from the API
/// perspective it feels like reading/writing from/to contiguous memory.
fn split_on_page_boundaries(address: u64, size: u64) -> Vec<(u64, u64)> {
    let mut addrs = Vec::new();
    let mut curr_size = size;
    let mut curr_addr = address;
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
    }

    addrs
}

fn get_pdb(name: &str, hash: &str) -> File {
    let windows_path = format!("C:\\Symbols\\{}\\{}\\{}", name, hash, name);
    let wsl_path = format!("/mnt/c/Symbols/{}/{}/{}", name, hash, name);
    if let Ok(file) = File::open(windows_path) {
        file
    } else {
        File::open(wsl_path).expect("Unable to open PDB")
    }
}

fn main() -> std::io::Result<()> {
    let mut phys_file = File::open("../snapshot/snapshot.phys").expect("FILE NOT FOUND: snapshot.phys");
    let mut file = File::open("../snapshot/SNAPSHOT_regs").expect("FILE NOT FOUND: snapshot_regs");
    let mut regs_data = Vec::new();
    file.read_to_end(&mut regs_data).expect("Unable to read snapshot regs file");

    let vbcpu = unsafe { &*(regs_data.as_ptr() as *const Vbcpu) };

    let cr3 = vbcpu.cr3 & 0xffff_ffff_ffff_f000;
    let lma = true;
    let gs_base = vbcpu.gs.base;
    let cs = vbcpu.cs.sel;
    println!("cr3: {:#x} cs: {:#x}", cr3, cs);

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

    let cr3_file = format!("cache/{:#x}.cr3", user_modules_hash);
    let kernel_cr3 = match File::open(&cr3_file) {
        Ok(mut file) => {
            let mut buffer = [0; 8];
            file.read_exact(&mut buffer);
            u64::from_le_bytes(buffer)
        }
        Err(_) => {
            let kernel_cr3 = get_kernel_cr3(&mut phys_file).expect("Unable to get kernel_cr3");
            let mut file = File::create(cr3_file).expect("Unable to open cr3 file");
            file.write_all(&kernel_cr3.to_le_bytes());
            kernel_cr3
        }
    };

    print!("Kernel cr3: {:#x}\n", kernel_cr3);

    let kernel_modules = get_kernel_modules(&mut phys_file, user_modules_hash);
    print!("{:#x?}\n", kernel_modules);
    for (r, module) in kernel_modules.iter() {
        if module == "ntoskrnl.exe" {
            print!("{:x?} {}\n", r, module);
            break;
        }
    }

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .expect("Capstone failed to init");

    let mut last_user_rip = 0;

    let args: Vec<_> = std::env::args().collect();
    let mut verbose = false;
    let mut file;
    if args.len() == 2 {
        if args[1].contains("verbosetrace") { verbose = true; }
        file = File::open(&args[1]).expect("Unable to open user trace");
    } else {
        if verbose {
            file = File::open("../tftp-server/test.verbosetrace").expect("Unable to open test.verbosetrace");
        } else {
            file = File::open("../tftp-server/test.trace").expect("Unable to open test.trace");
        }
    }

    let mut data = vec![];
    file.read_to_end(&mut data);

    let regs: Vec<VmRegs> = if data.len() % std::mem::size_of::<VmRegs>() == 0 {
        unsafe {
            Vec::from_raw_parts(
                data.as_mut_ptr() as *mut VmRegs,
                data.len() / std::mem::size_of::<VmRegs>(),
                data.capacity(),
            )
        }
    } else {
        let mut result = Vec::new();
        for bytes in data.chunks(8) {
            let mut new_reg = VmRegs::default();
            new_reg.rip = u64::from_le_bytes(bytes.try_into().unwrap());
            result.push(new_reg);
        }
        result
    };

    println!("regs.len(): {}", regs.len());

    // let mut indent = 0;
    let regs_len = regs.len();
    let mut rip = String::from("NA");

    let mut symbols = HashMap::new();

    // Populate the pdb database with the current version modules
    let mut pdbs = HashMap::new();
    let data = include_str!("../../parse_trace/versions/windows.system32");
    for line in data.lines() {
        if line.len() == 0 { continue; }
        let name = line.split(" ").nth(0).unwrap();
        let hash = line.split(" ").nth(1).unwrap();
        pdbs.insert(name, hash);
    }

    let all_pdbs = [
        "win32kfull.sys",
        "ntoskrnl.exe",
        "user32.dll",
        "win32k.sys",
        "win32kbase.sys",
        "kernelbase.dll",
        "ntdll",
        "ntdll.dll",
        "gdi32.dll",
        "gdi32full.dll",
    ];

    // Gather all symbols from the PDBs
    for name in &all_pdbs {
        let mut curr_symbols = HashMap::new();

        // Pdb binary replacement to pdb
        let mut pdb_name = name.replace(".dll", ".pdb").replace(".sys", ".pdb");

        // print!("pdb_name: {}\n", pdb_name);
        // Hard code check for ntoskrnl
        if pdb_name == "ntoskrnl.exe" { 
            pdb_name = "ntkrnlmp.pdb".to_string()
        }
        if pdb_name.contains("ntdll_") { 
            pdb_name = "ntdll.pdb".to_string()
        }
        if !pdb_name.ends_with(".pdb") { pdb_name += ".pdb" }
        // print!("pdb_name: {}\n", pdb_name);

        // Get the PDB symbols from the PDB file
        let pdb_hash = pdbs.get(pdb_name.as_str()).expect(&format!("Unable to get PDB: {}", name));
        let mut pdb_file = get_pdb(&pdb_name, pdb_hash);
        let mut pdb_symbols = get_pdb_symbols(&pdb_file);
        pdb_symbols.sort();

        // Insert the range for this given PDB
        let num_symbols = pdb_symbols.len();
        for i in 0..num_symbols {
            let start = pdb_symbols[i].0;
            let end = if i == num_symbols - 1 {
                0xffffffff
            } else {
                pdb_symbols[i+1].0
            };
            let diff = end - start;
            curr_symbols.insert(start..start+diff, pdb_symbols[i].1.clone());
        }

        symbols.insert(name.to_lowercase(), curr_symbols);
    }

    let mut first_timers = Vec::new();

    for (i, reg) in regs.iter().enumerate() {
        let curr_rip = reg.rip;
        let curr_modules = match (curr_rip >> 63) & 1 {
            0 => { &user_modules }
            1 => { &kernel_modules }
            _ => unreachable!()
        };

        let mut rip = String::from("????????");

        // Check if the current RIP is in a module we know about
        'top: for (check, module) in curr_modules.iter() {
            let module = module.to_lowercase();

            // Check if the current module address range contains RIP
            if check.contains(&curr_rip) {

                // Get the offset into the module
                let curr_offset = curr_rip-check.start;

                // Check if we have symbols for the current module
                if symbols.contains_key(&module) {
                    // Get the symbols for the current module
                    let curr_symbols = symbols.get(&module).unwrap();

                    // Look up which symbol contains the current RIP
                    for (range, symbol) in curr_symbols.iter() {
                        if range.contains(&(curr_offset as u32)) {
                            let mut firsttime = "";
                            if curr_offset - range.start as u64 == 0 {
                                // Construct module!function+offset
                                let check = format!("{}!{}+{:#x}", module, symbol, 
                                    curr_offset - range.start as u64);

                                // If this is the first time this symbol has been seen, mark it
                                if !first_timers.contains(&check) {
                                    firsttime = "FIRSTTIME";
                                    first_timers.push(check);
                                }
                            }

                            // Example: 
                            // ntoskrnl.exe!KiPageFault+0x72, (ntoskrnl.exe+0x3ab632)  
                            rip = format!("{}!{}+{:#x}, ({}+{:#x}) {}", module, symbol, 
                                curr_offset - range.start as u64, module, curr_offset, firsttime);
                            break 'top;
                        }
                    }

                    rip = format!("{}+{:#x}, ({:#x})", module, curr_offset, curr_rip);
                } else {
                    rip = format!("{}+{:#010x}, ({:#x})", module, curr_offset, curr_rip);
                }
                break;
            }
        }

        // Use the kernel cr3 if a kernel address (highest bit set), otherwise use userland cr3
        let (curr_cr3, other_cr3) = match reg.rip >> 63 & 1 {
            0 => { 
                last_user_rip = reg.rip;
                (cr3, kernel_cr3) 
            }
            1 => { (kernel_cr3, cr3) }
            _ => unreachable!()
        };

        // Read 16 bytes for the current instruction
        let offset = reg.rip & 0xfff;
        let mut curr_instr_bytes = [0; 16];
        let res = phys_file.read_mem(Address::Virtual(reg.rip, curr_cr3), &mut curr_instr_bytes);
        if res.is_err() {
            phys_file.read_mem(Address::Virtual(reg.rip, other_cr3), &mut curr_instr_bytes);
        }

        // Disassemble the found bytes for 1 instruction
        let disasm = cs.disasm_count(&curr_instr_bytes, reg.rip, 1).unwrap();

        if !verbose {
            print!("[{}][{:#x}] {} ", i, last_user_rip, rip);
            for i in disasm.iter() {
                print!("{}", i);
                // let msg = &format!("{}", i);
                /*
                if msg.contains("call") { 
                    indent += 1;
                }
                if msg.contains("ret") {
                    indent = indent.saturating_sub(1);
                }
                */
            }
            print!("\n");
        } else {
            reg.print();
            print!("[{}][{:#x}] {} ", i, last_user_rip, rip);
            for i in disasm.iter() {
                print!("{}", i);
            }
            print!("\n");
        }
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


#[derive(Clone, Copy, Debug, Default)]
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

            print!(
                "gs_base: {:<#18x} kernel_gs_base: {:<#18x}\n",
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
