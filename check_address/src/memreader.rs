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

#[derive(Debug, Clone, Copy)]
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
                let res = self.translate(addr.clone());
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

        // print!("Vaddr: {:x?}\n", addr);
        /* For each level in the page table */
        for (_depth, curr_offset) in cr_offsets.iter().enumerate() {
            /* Get the page table entry */
            let start_offset = (curr_page + (curr_offset * 8)) as usize;

            // print!("start_offset: {:#x} -- ", start_offset);
            let entry = self.read_u64(Address::Physical(start_offset as u64));
            // print!("{:#x}\n", entry);
            if entry & 1 == 0 { 
                // Entry not present
                if _depth > 0 {
                    print!("[{}][{:x?}] {:#x} NOT PRESENT\n", _depth, cr_offsets, vaddr);
                }
                return None; 
            }

            /* Get the physical address of the next level */
            if entry >> 7 & 1 == 1 {
                curr_page = (entry & 0xffff_ffe0_0000) | (vaddr & 0x1f_ffff);
                // print!("[LargePage] {:#x}", curr_page);
                return Some(curr_page as usize);
            }

            // println!("entry: {:#x}", entry);
            curr_page = entry & 0xffff_ffff_f000;
            // println!("entry: {:#x}", curr_page);
            if curr_page == 0 {
                print!("NOT FOUND\n");
                return None
            }
        }

        Some(curr_page as usize + (vaddr as usize & 0xfff))
    }
}

impl MemReader for File {}
