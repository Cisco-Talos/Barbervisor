extern crate noodle;
use noodle::{Serialize, Deserialize};

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let mut largest_size = 0;
    let mut largest_file = PathBuf::new();
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    const OUTPUT_FILE: &'static str = "corpus.corpgen";
    for entry in fs::read_dir(".")? {
        let curr_path = entry?.path();
        if curr_path.is_dir() { continue; }

        // No need to add the binary or the output file to the corpus
        if curr_path.to_str().unwrap().contains("corpgen") { continue; }

        // Read the current file 
        let mut data = Vec::new();
        let mut file = fs::File::open(&curr_path)?;
        file.read_to_end(&mut data)?;

        // Check if this file is the largest in the corpus
        print!("{:?} {}\n", curr_path, data.len());
        if largest_size < data.len() {
            largest_size = data.len();
            largest_file = curr_path;
        }

        // Add the current file to the corpus
        corpus.push(data);
    }

    // Serialize the corpus to disk
    let mut ser = Vec::new();
    corpus.serialize(&mut ser);

    let mut output = fs::File::create(OUTPUT_FILE)?;
    output.write_all(&ser)?;

    // Write the stats of the corpus
    print!("Number of files: {}\n", corpus.len());
    print!("Largest: {} -- {:?}\n", largest_size, largest_file);
    print!("Size of serialized: {}\n", ser.len());
    print!("Corpus written to {}\n", OUTPUT_FILE);

    Ok(())
}

