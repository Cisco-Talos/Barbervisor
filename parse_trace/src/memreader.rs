use std::io::{Seek, SeekFrom, Read};
use std::string::String;
use std::fs::File;

#[derive(Debug)]
pub struct Module {
    name: String,
    fullname: String,
    address: u64,
    length: u64
}

#[derive(Debug)]
pub enum Address {
    /// Physical address
    Physical(u64),

    /// Virtual address and CR3
    Virtual(u64, u64)
}

pub trait MemReader: Read + Seek {
    /// Read a u64 at the given Address
    fn read_u64(&mut self, addr: Address) -> u64 {
        let mut buffer = [0u8; 8];
        self.read_mem(addr, &mut buffer).expect("Error on read_u64");
        u64::from_le_bytes(buffer)
    }

    /// Read a u32 at the given Address
    fn read_u32(&mut self, addr: Address) -> u32 {
        let mut buffer = [0u8; 4];
        self.read_mem(addr, &mut buffer).expect("Error on read_u64");
        u32::from_le_bytes(buffer)
    }

    /// Read into a buffer at the given address. Assumes wanting to read into the
    /// entire buffer.
    fn read_mem(&mut self, addr: Address, buffer: &mut [u8]) -> Result<(), ()> {
        let paddr = match addr {
            Address::Physical(paddr) => paddr,
            Address::Virtual(_vaddr, _cr3) => {
                let res = self.translate(addr);
                if res.is_none() { return Err(()); }
                res.unwrap() as u64
            }
        };

        self.seek(SeekFrom::Start(paddr)).expect("Unable to seek in read");
        self.read_exact(buffer).expect("Unable to read_exact for read");
        Ok(())
    }

    /// Returns the virtual addresses and the virt to phys tranlations mapping from
    /// the data of a vbox core file
    fn translate(&mut self, addr: Address) -> Option<usize> {
        let (vaddr, mut curr_page) = match addr {
            Address::Virtual(vaddr, curr_page) => (vaddr, curr_page),
            Address::Physical(_x) => panic!("Cannot translate from Physical address")
        };

        // print!("[translate] addr: {:x?}\n", addr);

        /* Calculate the components for each level of the page table from the vaddr. */
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

            // print!("start_offset: {:#x} -- ", start_offset);
            let entry = self.read_u64(Address::Physical(start_offset as u64));
            // print!("entry: {:#x}\n", entry);
            if entry & 1 == 0 { 
                // Entry not present
                return None; 
            }

            /* Get the physical address of the next level */
            if entry >> 7 & 1 == 1 {
            // if entry & 1 << 7 > 0 {
                curr_page = (entry & 0xffff_ffe0_0000) | (vaddr & 0x1f_ffff);
                // print!("[LargePage] ");
                return Some(curr_page as usize);
            }

            curr_page = entry & 0xffff_ffff_f000;
            // println!("entry: {:#x}", curr_page);
            if curr_page == 0 {
                return None
            }
        }

        // println!("  -> {:#x}", curr_page);
        Some(curr_page as usize + (vaddr as usize & 0xfff))
    }
}

impl MemReader for File {}

/*
fn main() -> std::io::Result<()> {
    let mut file =  std::fs::File::open("/Users/user/workspace/barberslice/snapshot/snapshot.phys")?;

    let mut buffer = [0u8; 0x1000];
    let needle = "\\SystemRoot\\system32\\nt";
    let needle: Vec<u8> = needle.bytes().collect();
    let needle_len = needle.len();
    let kdbg;
    let mut kernel_cr3 = None;

    // From Volatility3's documentation (DTB - Directory Table Base aka Kernel cr3)
    //
    // New versions of windows, with randomized self-referential pointers, appear to 
    // always load their dtb within a small specific range (`0x1a0000` and `0x1b0000`), 
    // so instead we scan for all self-referential pointers in that range, and ignore any 
    // that contain multiple self-references (since the DTB is very unlikely to point to 
    // itself more than once).
    for counter in (0x1a0000..0x1b0000).step_by(0x1000) {
        for i in (0..0x1000).step_by(8) {
            let curr_ptr = file.read_u64(
                Address::Physical(counter + i)) & 0xffff_ffff_f000;
            if curr_ptr == counter {
                print!("DTB (kernel_cr3) [{:#x}]: {:#x}\n", counter + i as u64, counter);
                kernel_cr3 = Some(counter);
                break;
            }
        }
    }

    print!("KCR3: {:x?}\n", kernel_cr3);
    let kernel_cr3 = kernel_cr3.unwrap();
    let mut counter = 0;

    'leave: loop {
        file.read_mem(Address::Physical(counter), &mut buffer)
            .expect(&format!("Unable to read addr looking for KDBG: {:#x}", counter));
        for i in 0..0x1000-needle_len {
            if &buffer[i..i+needle_len] == needle.as_slice() {
                let check_addr = (counter + i as u64).saturating_sub(0x18);
                let possible_kdbg = file.read_u64(Address::Physical(check_addr)) 
                    & 0xffff_ffff_ffff;
                let mut fileheader = [0; 2];
                let res = file.read_mem(Address::Virtual(possible_kdbg, kernel_cr3), 
                              &mut fileheader);
                if res.is_err() { continue; }
                if fileheader == ['M' as u8, 'Z' as u8] {
                    print!("KDBG [{:#x}]: {:#x}\n", counter + i as u64, possible_kdbg);
                    kdbg = Some(possible_kdbg);
                    break 'leave;
                }
            }
        }
        counter += 0x1000;
    }

    print!("KDBG: {:x?}\n", kdbg);

    // Attempt to brute force the offset of PsLoadedModuleList rather than
    // downloading the PDB for this ntoskrnl.exe and using that
    let mut psloadedmodulelist_offset = 0;
    for offset in (0..0x1000_0000).step_by(2) {
        let psloadedmodulelist = kdbg.unwrap() + offset;
        let psloadedmodulelist_phys = file.translate(
            Address::Virtual(psloadedmodulelist, kernel_cr3));

        // If translate_phys was null, continue to look
        if psloadedmodulelist_phys.is_none() { continue; }
    
        // Guarenteed to be some now
        let psloadedmodulelist_phys = psloadedmodulelist_phys.unwrap() as u64;

        // print!("_phys {:#x}\n", psloadedmodulelist_phys);
        let ldr_data_table_entry = file.read_u64( 
            Address::Physical(psloadedmodulelist_phys)) & 0xffff_ffff_ffff;
        let ldr_data_table_entry_phys = file.translate(
            Address::Virtual(ldr_data_table_entry, kernel_cr3));

        // If translate_phys was null, continue to look
        if ldr_data_table_entry_phys.is_none() { continue; }

        // Guarenteed to be some now
        let ldr_data_table_entry_phys = ldr_data_table_entry_phys.unwrap() as u64;

        let data_entry = KldrDataTableEntry::from_reader(ldr_data_table_entry_phys, 
            &mut file);

        if data_entry.flink >> 63 == 0 { continue; }
        if data_entry.blink >> 63 == 0 { continue; }

        let curr_base = data_entry.base_dll(kernel_cr3, &mut file);
        if curr_base.is_none() { continue; }

        // If the first dll is ntoskrnl.exe, we assume we have found the right offset
        if "ntoskrnl.exe" == curr_base.unwrap() {
            print!("Found PsLoadedModuleList: {:#x}\n", offset);
            psloadedmodulelist_offset = offset;
            break;
        }
    }

    assert!(psloadedmodulelist_offset > 0, "Failed to find PsLoadedModuleList offset");
    print!("PSML offset: {:x?}\n", psloadedmodulelist_offset);

    let mut psloadedmodulelist = kdbg.unwrap() + psloadedmodulelist_offset;
    let mut found = HashSet::new();
    let mut modlist = HashMap::new();

    loop {
        let psloadedmodulelist_phys = file.translate(
            Address::Virtual(psloadedmodulelist, kernel_cr3)).unwrap() as u64;
        let data_entry = KldrDataTableEntry::from_reader(psloadedmodulelist_phys, 
                                                        &mut file);

        // Set the next loop address in case we can't resolve the base dll or full dll
        psloadedmodulelist = data_entry.flink;
        let base_dll = match data_entry.base_dll(kernel_cr3, &mut file) {
            None => continue,
            Some(dll) => dll
        };

        let _full_dll = match data_entry.full_dll(kernel_cr3, &mut file) {
            None => continue,
            Some(dll) => dll
        };

        let dll_base = data_entry.dll_base;
        let size = data_entry.size_of_image;
        modlist.insert(dll_base..dll_base+size, base_dll.to_string());

        if !found.insert(base_dll) {
            break;
        }
    }
    
    print!("{:x?}\n", modlist);
    print!("{}\n", modlist.len());

    Ok(())
}
*/
