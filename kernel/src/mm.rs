use crate::acpi;
use alloc::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering, AtomicBool};
use mmu::PhysMem;

pub struct GlobalAllocator;

/// Physical memory implementation
///
/// This is used during page table operations
pub struct Pmem;

/// Physical memory implementation
///
/// This is used during page table operations
pub struct Ept;

pub static mut PMEM: Pmem = Pmem;
static PMEM_LOCK: AtomicBool = AtomicBool::new(false);

/// Allocate a new zeroed out page and return it
pub fn alloc_page() -> Option<&'static mut [u8; 4096]> {
    let res = unsafe {
        if let Some(page) = PMEM.alloc_page() {
            let page = &mut *(page as *mut [u8; 4096]);
            *page = [0x0u8; 4096];
            Some(page)
        } else {
            None
        }
    };


    res
}

/// Allocate n bytes
pub fn alloc(_size: usize) -> Option<u64> {
     panic!("Calling alloc N\n");
}

impl mmu::PhysMem for Pmem {
    /// Allocate a page
    fn alloc_page(&mut self) -> Option<*mut u8> {
        let res = unsafe {
            // Get current node id
            let node_id = acpi::get_node_id(cpu::get_apic_id());

            // Get an allocation on the current node
            let alloc = acpi::node_alloc_page(node_id.unwrap_or(0));
            if alloc.is_null() {
                None
            } else {
                Some(alloc as *mut u8)
            }
        };


        res
    }

    /// Read a 64-bit value at the physical address specified
    fn read_phys(&mut self, addr: *mut u64) -> Result<u64, &'static str> {
        unsafe { Ok(core::ptr::read(addr)) }
    }

    /// Write a 64-bit value to the physical address specified
    fn write_phys(&mut self, addr: *mut u64, val: u64) -> Result<(), &'static str> {
        let res = unsafe { Ok(core::ptr::write(addr, val)) };
        res
    }

    /// This is used to let the MMU know if we reserve memory outside of
    /// the page tables. Since we do not do this at all we always return true
    /// allowing any address not in use in the page tables to be used for
    /// ASLR.
    fn probe_vaddr(&mut self, _addr: usize, _length: usize) -> bool {
        true
    }
}

static PAGE_ALLOC_LOCK: AtomicUsize = AtomicUsize::new(0);
static PAGE_ALLOC_LOCK_REL: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for GlobalAllocator {
    /// Global allocator. Grabs free memory from E820 and removes it from the table.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout
            .size()
            .checked_add(0xfff)
            .expect("layout.size() checked_add failed")
            & !0xfff;
        assert!(size > 0, "Zero size allocations not allowed");

        while PMEM_LOCK.compare_exchange(false, true, 
                Ordering::Acquire, Ordering::Acquire).is_err() {
        }

        // Get access to the current page table
        let mut page_table = mmu::PageTable::from_existing(cpu::read_cr3() as *mut _, &mut PMEM);

        // Pick a random 64-bit address to return as the allocation
        let alc_base = page_table
            .rand_addr(size as u64)
            .expect("page_table rand_addr failed");

        page_table
            .add_memory(alc_base, size as u64)
            .expect("page_table.add_memory failed");

        // print!("Releasing lock in alloc\n");
        PMEM_LOCK.store(false, Ordering::Release);

        alc_base as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout
            .size()
            .checked_add(0xfff)
            .expect("dealloc checked_add failed")
            & !0xfff;
        assert!(size > 0, "Zero size allocations not allowed");
        let size = size as u64;

        while PMEM_LOCK.compare_exchange(false, true, 
                Ordering::Acquire, Ordering::Acquire).is_err() {
            // print!("Stuck in dealloc\n");
        }

        // Get access to the current page table
        let mut page_table = mmu::PageTable::from_existing(cpu::read_cr3() as *mut _, &mut PMEM);

        // Go through each page in the allocation and unmap it
        for ii in (0..size).step_by(4096) {
            let addr = ptr as u64 + ii;
            assert!((addr & 0xfff) == 0, "Non-page-aligned allocation");

            // Go through all physical pages that were removed
            for ppage in &page_table.unmap_page(addr).expect("Failed to unmap"){
                if let Some(ppage) = ppage {
                    // Get current node id
                    let node_id = acpi::get_node_id(cpu::get_apic_id()).unwrap_or(0);
                    acpi::node_free_page(node_id, (*ppage) as *mut u8);
                }
            }
        }

        PMEM_LOCK.store(false, Ordering::Release);
    }
}
