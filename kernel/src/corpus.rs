use alloc::vec::Vec;
use spin::Mutex;
use crate::Rng;
use crate::ni;
use crate::net;
use crate::Deserialize;

lazy_static! {
    pub static ref CORPUS: Mutex<Corpus> = Mutex::new(Corpus::new());
}

pub struct Corpus {
    pub inputs: Vec<Vec<u8>>
}

impl Corpus {
    pub fn new() -> Corpus {
        Corpus {
            inputs: Vec::new()
        }
    }

    /// Initialize the corpus with a file from the server.
    /// 
    /// This file should be created via the `corpgen` utility.
    pub fn init(&mut self, filename: &str) {
        print!("Getting corpus.. {}\n", filename);
        let corpus_data = net::get_file(filename);
        if corpus_data.len() == 0 { return; }
        let files = <Vec<Vec<u8>> as Deserialize>::deserialize(&mut corpus_data.as_slice()).unwrap();
        for f in files {
            self.insert(f);
        }
        print!("Init corpus with {} items\n", self.len());
    }

    /// Insert a sample into the corpus
    pub fn insert(&mut self, input: Vec<u8>) {
        self.inputs.push(input);
    }

    /// Get the number of samples in the corpus
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Get a random sample from the corpus
    pub fn rand_input(&self, rng: &mut Rng) -> Vec<u8> {
        let offset = rng.next() as usize % self.len();
        self.inputs[offset].clone()
    }

    /// Get a mutated sample from the corpus
    ///
    /// This will randomly choose one sample from the corpus and mutate it based on the C version
    /// of Radamsa (which was ported to Rust).
    pub fn mutated_input(&self) -> Vec<u8> {
        ni::mutate_samples(&self.inputs)
    }
}
