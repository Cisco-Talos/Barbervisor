//! Primitive trace mechanic used to sending VmReg traces to the TFTP server
use crate::net;
use crate::vmregs::VmRegs;
use alloc::vec::Vec;

fn as_u8_slice<T: Sized>(data: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((data as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

pub struct Trace {
    buff: alloc::vec::Vec<VmRegs>,
}

impl Trace {
    pub fn new() -> Trace {
        Trace {
            buff: alloc::vec::Vec::new(),
        }
    }

    /// Put the current trace on the TFTP server with the given filename
    pub fn put(&self, filename: &str) {
        let mut data: Vec<u8> = Vec::new();
        let mut file_index = 0;
        let mut curr_filename = format!("{}{}", filename, file_index);

        let chunk_size = 0xffff_ffff;
        let chunks = self.buff.len() / chunk_size;
        print!("Total chunks: {}\n", chunks);

        for (index, i) in self.buff.iter().enumerate() {
            for ch in as_u8_slice(&*i) {
                data.push(*ch);
            }
            if index > 0 && index % chunk_size == 0 {
                net::put_file(&curr_filename, &data);
                data.clear();
                file_index += 1;
                curr_filename = format!("{}{}", filename, file_index);
            }
        }

        net::put_file(&curr_filename, &data);
    }

    /// Put the last N items from current trace on the TFTP server with the given filename
    pub fn put_n(&self, filename: &str, n: usize) {
        let n = if self.buff.len() < n {
            self.buff.len()
        } else {
            n
        };
        let mut data: Vec<u8> = Vec::new();
        for i in self.buff[self.buff.len() - n..].iter() {
            for ch in as_u8_slice(&*i) {
                data.push(*ch);
            }
        }
        net::put_file(filename, &data);
    }

    /// Returns the number of elements in the trace
    pub fn len(&self) -> usize {
        self.buff.len()
    }

    /// Add a VmRegs to the trace
    pub fn push(&mut self, regs: VmRegs) {
        self.buff.push(regs);
    }

    /// Pops the last element off the trace buffer
    pub fn pop(&mut self) {
        let _ = self.buff.pop();
    }

    /// Clears the current trace buffer
    pub fn clear(&mut self) {
        self.buff.clear();
    }
}
