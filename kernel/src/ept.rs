//! Extended Page Table
//!
//! Provides an Extended Page Table implementation. Used to translate Guest Physical
//! addresses to Kernel Physical addresses. Each page mapped in the EPT is currently
//! marked as READ | WRITE | EXECUTE.
//!
// use crate::dbg;
use crate::{GuestPhysical, KernelPhysical};
use mmu::PhysMem;
use x86_64::registers::model_specific::Msr;
use crate::msr::*;

lazy_static! {
    pub static ref CAPABILITIES: EptCapabilities = EptCapabilities::new();
    pub static ref DIRTY_PAGES: bool = CAPABILITIES.dirty_pages();
}

extern crate cpu;

#[derive(Copy, Clone)]
pub enum EptpMemoryType {
    Uncacheable = 0,
    WriteBack = 6,
}

pub struct EPTP {
    memory_type: EptpMemoryType,
    walk_length: u8,
    access_and_dirty_flag: u8,
    p4: u64,
}

impl EPTP {
    pub fn new(p4: u64) -> EPTP {
        EPTP {
            memory_type: EptpMemoryType::WriteBack,
            walk_length: 4 - 1,
            access_and_dirty_flag: *DIRTY_PAGES as u8,
            p4,
        }
    }

    pub fn as_ptr(&self) -> u64 {
        (self.p4)
            | ((self.access_and_dirty_flag) << 6) as u64
            | (self.walk_length << 3) as u64
            | self.memory_type as u64
    }
}

bitflags! {
    /// Possible flags for a page table entry.
    pub struct EptFlags: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const ACCESSED = 1 << 8;
        const DIRTY = 1 << 9;
        const EXECUTE2 = 1 << 10;
    }
}

/// A 64-bit page table entry.
#[derive(Clone)]
#[repr(transparent)]
pub struct EptEntry {
    pub entry: u64,
}

impl EptEntry {
    /// Creates an unused extended page table entry.
    pub fn new() -> Self {
        EptEntry { entry: 0 }
    }

    /// Creates an extended page table entry from an existing u64
    pub fn from(entry: u64) -> Self {
        EptEntry { entry }
    }

    /// Creates an extended page table entry from an address and flags
    pub fn from_addr(addr: u64, flags: EptFlags) -> Self {
        let mut entry = EptEntry::new();
        entry.set_addr(addr, flags);
        entry
    }

    /// Returns whether this entry is zero.
    pub fn is_unused(&self) -> bool {
        self.entry == 0
    }

    /// Sets this entry to zero.
    pub fn set_unused(&mut self) {
        self.entry = 0;
    }

    /// Returns the flags of this entry.
    pub fn flags(&self) -> EptFlags {
        EptFlags::from_bits_truncate(self.entry)
    }

    /// Returns the physical address mapped by this entry, might be zero.
    pub fn addr(&self) -> u64 {
        self.entry & 0x000fffff_fffff000
    }

    /// Insert EptFlag into this entry, while preserving the existing flags
    ///
    /// Example:
    ///
    /// Set the Accessed and Dirty flags into the entry
    ///
    /// ept_entry.flags()
    /// => READ | WRITE
    /// ept_entry.insert_flags(EptFlags::ACCESSED | EptFlags::DIRTY);
    /// ept_entry.flags()
    /// => READ | WRITE | ACCESSED | DIRTY
    pub fn insert_flags(&mut self, flags: EptFlags) {
        let mut curr_flags = self.flags();
        curr_flags.insert(flags);
        self.set_flags(curr_flags);
    }

    /// Remove EptFlag into this entry, while preserving the existing flags
    ///
    /// Example:
    ///
    /// Remove the Accessed and Dirty flags from the entry
    ///
    /// ept_entry.flags()
    /// => READ | WRITE | ACCESSED | DIRTY
    /// ept_entry.remove_flags(EptFlags::ACCESSED | EptFlags::DIRTY);
    /// ept_entry.flags()
    /// => READ | WRITE
    pub fn remove_flags(&mut self, flags: EptFlags) {
        let mut curr_flags = self.flags();
        curr_flags.remove(flags);
        self.set_flags(curr_flags);
    }

    /// Map the entry to the specified physical address with the specified flags.
    pub fn set_addr(&mut self, addr: u64, flags: EptFlags) {
        self.entry = addr | flags.bits();
    }

    /// Sets the flags of this entry, without preserving existing flags
    pub fn set_flags(&mut self, flags: EptFlags) {
        self.entry = self.addr() | flags.bits();
    }
}

/// Valid page mapping sizes
pub enum MapSize {
    Mapping1GiB,
    Mapping2MiB,
    Mapping4KiB,
}

/// Structure representing a page table
pub struct ExtendedPageTable<'a, T: 'a + PhysMem> {
    backing: *mut u64,
    physmem: &'a mut T,
}

impl<'a, T: 'a + PhysMem> ExtendedPageTable<'a, T> {
    /// Create a new, empty page table
    ///
    /// Unsafe as it is up to the caller to make sure the alloc_page() function
    /// actually correctly allocates pages.
    pub unsafe fn new(physmem: &'a mut T) -> ExtendedPageTable<'a, T> {
        let backing = physmem
            .alloc_page()
            .expect("Unable to alloc_page for physmem");

        core::ptr::write_bytes(backing, 0, 4096);

        ExtendedPageTable {
            physmem,
            backing: backing as *mut u64,
        }
    }

    /// Allocate and set all bytes in the page to zero
    pub unsafe fn alloc_zeroed_page(&mut self) -> *mut u64 {
        let ret = self
            .physmem
            .alloc_page()
            .expect("Unable to alloc zeroed page");

        let page = &mut *(ret as *mut [u8; 4096]);
        *page = [0x0u8; 4096];

        ret as *mut u64
    }

    /// Create an ExtendedPageTable from a u64 address
    pub unsafe fn from_existing(backing: *mut u64, physmem: &'a mut T) -> ExtendedPageTable<'a, T> {
        ExtendedPageTable { physmem, backing }
    }

    /// Get a pointer to the root page table for this page table. This value
    /// is what would be put in cr3.
    pub fn get_backing(&self) -> *mut u64 {
        self.backing
    }

    /// Create a mapping at `vaddr` in this page table containing the raw
    /// entry `entry`. This can be used to map large pages by using `mapsize`
    pub fn map_page_raw(
        &mut self,
        vaddr: u64,
        entry: u64,
        mapsize: MapSize,
        allow_remap: bool,
    ) -> Result<(), &'static str> {
        unsafe {
            // Check for address to be canon. Technically this does not matter
            // as we don't operate on the top bits, but there should be no
            // instance where get a non-canon address for mapping, so alert
            // the user.
            // 
            assert!(
                vaddr == cpu::canonicalize_address(vaddr),
                "Address is not canonical"
            );

            // Grab the page table backing
            let mut cur = self.backing;

            // All mappings must be at least 4k aligned
            assert!((vaddr & 0xfff) == 0, "Mapping vaddr not 4k aligned");
            // Validate that 1GiB and 2MiB mappings have the PS bit set 

            // Calculate the components for each level of the page table from the vaddr.
            let cr_offsets: [u64; 4] = [
                ((vaddr >> 39) & 0x1ff),
                ((vaddr >> 30) & 0x1ff),
                ((vaddr >> 21) & 0x1ff),
                ((vaddr >> 12) & 0x1ff),
            ];

            // Set the maximum table depth, as well as validate alignment for larger pages.
            let max_depth = match mapsize {
                MapSize::Mapping1GiB => {
                    assert!(
                        cr_offsets[2] == 0 && cr_offsets[3] == 0,
                        "1 GiB mapping not 1 GiB aligned"
                    );
                    1
                }
                MapSize::Mapping2MiB => {
                    assert!(cr_offsets[3] == 0, "2 MiB mapping not 2 MiB aligned");
                    2
                }
                MapSize::Mapping4KiB => 3,
            };

            // For each of the top level tables in the page table 
            for cr_depth in 0..max_depth {
                let cur_offset = cr_offsets[cr_depth];

                // Get the current entry 
                let ent = self.physmem.read_phys(cur.offset(cur_offset as isize))?;

                if ent == 0 {
                    // If there was no entry present, create a new page table
                    let new_pt = self.alloc_zeroed_page() as *mut u64;

                    let ept_entry = EptEntry::from_addr(
                        new_pt as u64,
                        EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE,
                    );

                    // Create page table with RWX permissions
                    self.physmem
                        .write_phys(cur.offset(cur_offset as isize), ept_entry.entry)?;

                    cur = new_pt;
                } else {
                    // Get the address of the next level page table.
                    cur = (ent & 0xFFFFF_FFFF_F000) as *mut u64;
                }
            }

            // Read the translation
            if !allow_remap {
                let old_entry = self
                    .physmem
                    .read_phys(cur.offset(cr_offsets[max_depth] as isize))?;

                if old_entry != 0 {
                    print!(
                        "vaddr: {:#x} old: {:#x} new: {:#x}\n",
                        vaddr, old_entry, entry
                    );
                }
                assert!(old_entry == 0, "Page already mapped");
            }

            // Commit the new entry
            self.physmem
                .write_phys(cur.offset(cr_offsets[max_depth] as isize), entry)?;

            // If we allowed remapping we must invlpg. If we did not allow
            // remapping we do not have to as the page can only transition from
            // unmapped to mapped and thus will not be in the TLB

            if allow_remap {
                cpu::invlpg(vaddr as usize);
            }
        }

        Ok(())
    }

    /// Translate a virtual address to a physical address using this page table
    /// Optionally dirty pages as we walk performing the translation.
    ///
    /// Returns a tuple of (physical address, page size)
    pub fn virt_to_phys_dirty(
        &mut self,
        vaddr: GuestPhysical,
        dirty: bool,
    ) -> Result<Option<KernelPhysical>, &'static str> {
        let vaddr = vaddr.0;

        unsafe {
            let mut cur = self.backing;

            // Non-canonical addresses not translatable
            assert!(
                cpu::canonicalize_address(vaddr) == vaddr,
                &format!("Virtual address to virt_to_phys() not canonical: {:#x}", vaddr)
            );

            // Calculate the components for each level of the page table from the vaddr.
            let cr_offsets: [u64; 4] = [
                ((vaddr >> 39) & 0x1ff), /* 512 GiB */
                ((vaddr >> 30) & 0x1ff), /*   1 GiB */
                ((vaddr >> 21) & 0x1ff), /*   2 MiB */
                ((vaddr >> 12) & 0x1ff), /*   4 KiB */
            ];

            // For each level in the page table
            for (_depth, cur_offset) in cr_offsets.iter().enumerate() {
                // Get the page table entry 
                let entry = self
                    .physmem
                    .read_phys(cur.offset(*cur_offset as isize))
                    .expect("Failed to read phys");
                let mut ept_entry = EptEntry::from(entry);


                // If the entry is not present return None
                if ept_entry.is_unused() {
                    return Ok(None);
                }

                // Entry was present, dirty it
                if dirty {
                    ept_entry.insert_flags(EptFlags::DIRTY | EptFlags::ACCESSED);

                    self.physmem
                        .write_phys(cur.offset(*cur_offset as isize), ept_entry.entry)?;
                }

                // Get the physical address of the next level
                cur = ept_entry.addr() as *mut u64;
            }

            // print!("[virt_to_phys][{}] {:#x}\n", 4, cur as u64 + (vaddr & 0xff));

            // Return out physical address of vaddr and the entry
            Ok(Some(KernelPhysical(cur as u64 + (vaddr & 0xfff))))
        }
    }

    /// Translate a virtual address to a physical address
    ///
    /// Return a tuple of (physical address, page size)
    pub fn virt_to_phys(
        &mut self,
        vaddr: GuestPhysical,
    ) -> Result<Option<KernelPhysical>, &'static str> {
        self.virt_to_phys_dirty(vaddr, false)
    }

    /// Create an identity map for up to `max_phys` bytes. This value will be
    /// rounded up to the nearest 1 GiB size and must not be zero.
    ///
    /// Since this is an identity map it starts at vaddr 0.
    pub fn add_identity_map(&mut self, max_phys: u64) -> Result<(), &'static str> {
        // 0 byte mapping not allowed
        assert!(max_phys > 0, "Attempted to add identity map of 0 bytes");

        // Round up to neareast 1GiB
        let max_phys = (max_phys + 0x3FFFFFFF) & !0x3FFFFFFF;

        for phys in (0..max_phys).step_by(0x40000000) {
            self.map_page_raw(
                phys,
                phys | (EptFlags::EXECUTE | EptFlags::WRITE | EptFlags::READ).bits(),
                MapSize::Mapping1GiB,
                false,
            )?;
        }

        Ok(())
    }

    /// Invoke a closure on each page present in this page table. Optionally if `dirty_only` is 
    /// true, the closure will only be invoked for dirty pages.
    ///
    /// XXX: This is marked unsafe until it is correct for tables with large pages.
    ///
    /// Dirty pages will be set to clean during the walk if `dirty_only` is true.
    pub unsafe fn for_each_page<F>(
        &mut self,
        dirty_only: bool,
        mut func: F,
        core_id: u32,
    ) -> Result<u64, &'static str>
    where
        F: FnMut(GuestPhysical, KernelPhysical, u32),
    {
        let mut pages = 0;
        let can_use_dirty = *DIRTY_PAGES;

        for pml4e in 0..512u64 {
            let ent = self.backing as *mut u64;
            let tmp = self.physmem.read_phys(ent.offset(pml4e as isize))?;
            let ept_entry = EptEntry::from(tmp);
            if ept_entry.is_unused() {
                continue;
            }

            if can_use_dirty && dirty_only {
                if !ept_entry.flags().contains(EptFlags::ACCESSED) {
                    continue;
                }
            }

            let ent = ept_entry.addr() as *mut u64;
            for pdpe in 0..512u64 {
                let tmp = self.physmem.read_phys(ent.offset(pdpe as isize))?;
                let ept_entry = EptEntry::from(tmp);
                if ept_entry.is_unused() {
                    continue;
                }

                if can_use_dirty && dirty_only {
                    if !ept_entry.flags().contains(EptFlags::ACCESSED) {
                        continue;
                    }
                }
                let ent = ept_entry.addr() as *mut u64;

                for pde in 0..512u64 {
                    let tmp = self.physmem.read_phys(ent.offset(pde as isize))?;
                    let ept_entry = EptEntry::from(tmp);
                    if ept_entry.is_unused() {
                        continue;
                    }
                    if can_use_dirty && dirty_only {
                        if !ept_entry.flags().contains(EptFlags::ACCESSED) {
                            continue;
                        }
                    }
                    let ent = ept_entry.addr() as *mut u64;

                    for pte in 0..512u64 {
                        let tmp = self.physmem.read_phys(ent.offset(pte as isize))?;
                        let mut ept_entry = EptEntry::from(tmp);
                        if ept_entry.is_unused() {
                            continue;
                        }

                        if can_use_dirty && dirty_only {
                            if !ept_entry.flags().contains(EptFlags::DIRTY) {
                                continue;
                            }
                            ept_entry.remove_flags(EptFlags::DIRTY | EptFlags::ACCESSED);

                            self.physmem
                                .write_phys(ent.offset(pte as isize), ept_entry.entry)?;
                        }

                        let vaddr = (pml4e << 39) | (pdpe << 30) | (pde << 21) | (pte << 12);
                        let paddr = tmp & 0xFFFFFFFFFF000;

                        pages += 1;
                        func(GuestPhysical(vaddr as u64), KernelPhysical(paddr), core_id);
                    }
                }
            }
        }

        Ok(pages)
    }

}

pub struct EptCapabilities {
    backing: u64
}

impl EptCapabilities {
    pub fn new() -> EptCapabilities {
        EptCapabilities {
            backing: unsafe { Msr::new(IA32_VMX_EPT_VPID_CAP).read() }
        }
    }

    pub fn dirty_pages(&self) -> bool{
        (self.backing >> 21) & 1 == 1
    }

    pub fn uncacheable(&self) -> bool{
        (self.backing >> 8) & 1 == 1
    }
}
