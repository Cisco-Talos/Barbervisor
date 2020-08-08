//! MsrBitmap helper module
//! Intel Manual: 24.6.9 MSR-Bitmap Address
//!
//! Example:
//!
//! // Default to all MSRs exit (all enabled)
//! let bitmap = MsrBitmap::new();
//!
//! // Clear 0xe7 msr so it doesn't VMExit on read or write
//! bitmap.clear_read(0xe7);
//! bitmap.clear_write(0xe7);
//!
use crate::mm;
use crate::tools::memcpy_slice;

pub struct MsrBitmap {
    backing: u64,
}

enum Quantity {
    Low,
    High,
}

enum Access {
    Read,
    Write,
}

impl MsrBitmap {
    pub fn new() -> MsrBitmap {
        let backing = mm::alloc_page()
            .expect("Failed to allocate msr low bitmap")
            .as_mut_ptr();

        /* Default to VMExit on NO MSRs*/
        unsafe { 
        core::ptr::write_bytes(backing, 0, 4096);
        }

        MsrBitmap { backing: backing as u64 }
    }

    pub fn get_backing(&self) -> u64 {
        self.backing
    }

    pub fn enable_all(&self) {
        memcpy_slice(self.backing as *mut u8, &[0xff; 0x1000]);
    }

    pub fn disable_all(&self) {
        memcpy_slice(self.backing as *mut u8, &[0x00; 0x1000]);
    }

    pub fn clear_read(&self, msr: u64) {
        self.clear_bit(Access::Read, msr);
    }

    pub fn clear_write(&self, msr: u64) {
        self.clear_bit(Access::Write, msr);
    }

    pub fn set_read(&self, msr: u64) {
        self.set_bit(Access::Read, msr);
    }

    pub fn set_write(&self, msr: u64) {
        self.set_bit(Access::Write, msr);
    }

    /// Clear the bit for the given MSR with the given Access
    fn clear_bit(&self, access: Access, msr: u64) {
        let quantity = match msr {
            0..0x1fff => Quantity::Low,
            0xc0000000..0xc0001fff => Quantity::High,
            _ => panic!("Unknown msr given"),
        };

        let address = match (access, quantity) {
            (Access::Read, Quantity::Low) => self.backing,
            (Access::Read, Quantity::High) => self.backing + 1024,
            (Access::Write, Quantity::Low) => self.backing + 2048,
            (Access::Write, Quantity::High) => self.backing + 3072,
        };

        let msr = msr & 0x1fff;
        let byte_offset = msr >> 3;
        let bit_offset = msr & 7;

        unsafe {
            *((address + (byte_offset as u64)) as *mut u8) &= !(1 << bit_offset);
        }
    }

    /// Set the bit for the given MSR with the given Access
    fn set_bit(&self, access: Access, msr: u64) {
        let quantity = match msr {
            0..0x1fff => Quantity::Low,
            0xc0000000..0xc0001fff => Quantity::High,
            _ => panic!("Unknown msr given"),
        };

        let address = match (access, quantity) {
            (Access::Read, Quantity::Low) => self.backing,
            (Access::Read, Quantity::High) => self.backing + 1024,
            (Access::Write, Quantity::Low) => self.backing + 2048,
            (Access::Write, Quantity::High) => self.backing + 3072,
        };

        let msr = msr & 0x1fff;
        let byte_offset = msr >> 3;
        let bit_offset = msr & 7;

        unsafe {
            *((address + (byte_offset as u64)) as *mut u8) |= 1 << bit_offset;
        }
    }
}
