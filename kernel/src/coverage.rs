use crate::HashSet;
use spin::Mutex;
use core::ops::Range;

use crate::vmregs::VmRegs;
use crate::net;
use alloc::vec::Vec;
use alloc::string::String;
use core::convert::TryInto;
use crate::time;
use crate::stats::LAST_COVERAGE;
use core::sync::atomic::Ordering;

pub enum CoverageType {
    All,
    User,
    Kernel,
    Ranges(Vec<Range<u64>>),
    None
}

fn as_u8_slice<T: Sized>(data: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((data as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

lazy_static! {
    pub static ref COVERAGE: Mutex<Coverage> = Mutex::new(Coverage::new());
}

pub struct Coverage {
    pub seen: HashSet<u64>,
    // seen: HashSet<VmRegs>,
    graph: Vec<u32>,
}

impl Coverage {
    /// Create a new Coverage
    pub fn new() -> Coverage {
        Coverage {
            seen: HashSet::new(),
            graph: Vec::new(),
        }
    }

    /// Initialize the Coverage based on a file
    pub fn init(&mut self, filename: &str) {
        let coverage_data = net::get_file(filename);
        if coverage_data.len() == 0 { return; }
        for i in (0..coverage_data.len()).step_by(8) {
            let data = u64::from_le_bytes(coverage_data[i..i+8].try_into().unwrap());
            self.seen.insert(data);
        }
        
        print!("Init coverage with {} items\n", self.len());

    }

    /// Get the length of the current coverage
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Insert RIP to the current coverage
    pub fn insert(&mut self, regs: &VmRegs) -> bool {
        let res = self.seen.insert(regs.get_rip());
        if res {
            // If we have new cov, mark down the current time for stats to print the time since 
            // last coverage
            LAST_COVERAGE.store(time::rdtsc(), Ordering::SeqCst);
        }
        res
    }

    /// Insert a given address into the coverage
    pub fn insert_addr(&mut self, addr: u64) -> bool {
        let res = self.seen.insert(addr);
        if res {
            // If we have new cov, mark down the current time for stats to print the time since 
            // last coverage
            LAST_COVERAGE.store(time::rdtsc(), Ordering::SeqCst);
        }
        res
    }

    /// Add another entry in the coverage graph for the current amount of coverage. Used for
    /// plotting graph
    pub fn mark_graph(&mut self) {
        self.graph.push(self.len() as u32);
    }

    /// Put the current trace on the TFTP server with the given filename
    pub fn put(&mut self, filename: &str) {
        let mut data = Vec::new();
        for addr in self.seen.iter() {
            data.extend(&addr.to_le_bytes());
        }

        // Generate the .graph file for GNUPlot
        let mut graph_data = String::new();
        for num in self.graph.iter() {
            graph_data.push_str(&format!("{}\n", num));
        }

        // Put the coverage address information
        net::put_file(&filename, &data);

        // Put the coverage len by second data
        net::put_file(&format!("{}.graph", filename), graph_data.as_bytes());
    }
}

