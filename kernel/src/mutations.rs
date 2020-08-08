//! Test helper for storing mutations used to fuzz one file rather than storing the entire
//! input test case. 
use alloc::vec::Vec;
use spin::Mutex;
use crate::Rng;
use crate::net;
use crate::{Serialize, Deserialize};

lazy_static! {
    pub static ref MUTATIONS: Mutex<Mutations> = Mutex::new(Mutations::new());
}

noodle!(serialize, deserialize,
#[derive(Clone, Copy)]
pub struct Mutation {
    /// Offset in file to mutate
    offset: u32,

    /// Byte to replace
    byte: u8
}
);

impl Mutation {
    pub fn new(offset: u32, byte: u8) -> Mutation {
        Mutation { offset, byte }
    }
}


pub struct Mutations {
    /// List of mutations [address; byte]
    pub mutations: Vec<Vec<Mutation>>
}

impl Mutations {
    pub fn new() -> Mutations {
        Mutations {
            mutations: Vec::new()
        }
    }

    /// Initialize the corpus with a file from the server.
    /// 
    /// This file should be created via the `corpgen` utility.
    pub fn init(&mut self, filename: &str) {
        print!("Getting corpus.. {}\n", filename);
        let corpus_data = net::get_file(filename);
        if corpus_data.len() == 0 { return; }
        let files = <Vec<Vec<Mutation>> as Deserialize>::deserialize(&mut corpus_data.as_slice());
        let files = files.unwrap();
        for f in files {
            self.insert(f);
        }
        print!("Init corpus with {} items\n", self.len());
    }

    /// Insert a sample into the corpus
    pub fn insert(&mut self, input: Vec<Mutation>) {
        self.mutations.push(input);
    }

    /// Get the number of samples in the corpus
    pub fn len(&self) -> usize {
        self.mutations.len()
    }

    /// Get a random sample from the corpus
    pub fn rand_input(&self, rng: &mut Rng) -> Vec<Mutation> {
        if self.len() == 0 {
            return Vec::new();
        }
        let offset = rng.next() as usize % self.len();
        self.mutations[offset].clone()
    }

    /// Sends the current mutations corpus to the server
    pub fn put_to_server(&self) {
        let mut data = Vec::new();
        self.mutations.serialize(&mut data);
        crate::net::put_file("corpus_mutations", &data);
    }
}

