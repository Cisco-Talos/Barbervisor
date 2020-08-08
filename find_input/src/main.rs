extern crate glob;
extern crate rayon;
extern crate noodle;

use noodle::{Serialize, Deserialize};
use std::fs::File;
use std::io::Read;
use std::path::{PathBuf, Path};
use glob::{glob_with, MatchOptions};
use rayon::prelude::*;

const WANTED: u64 = 0x7ffb_6791_0000 + 0x4bfd1;

fn find_coverage(path: &PathBuf) -> bool {
    let mut file = File::open(path).expect("Failed to open file");
    let mut coverage = Vec::new();
    file.read_to_end(&mut coverage).expect("Failed to read coverage");
    let cov = <Vec<[u64; 2]> as Deserialize>::deserialize(&mut coverage.as_slice()).unwrap();
    cov.iter().filter(|x| x[0] == WANTED).count() > 0
}

fn main() -> Result<(), ()> {
    let options: MatchOptions = Default::default();
    let files: Vec<_> = glob_with("../tftp-server/project/coverages/*.coverage", options).unwrap()
            .filter_map(|x| x.ok())
            .collect();

    if files.len() == 0 {
        panic!("No coverage files found");
    }

    let found: Vec<_> = files.par_iter()
                             .map(|path| (find_coverage(path), path))
                             .filter(|(x, path)| *x)
                             .map(|(x, path)| path)
                             .collect();

    let mut found_files = Vec::new();
    for f in found {
        let filename = f.as_path().file_stem().unwrap().to_str().unwrap();
        let new_path = format!("../tftp-server/project/inputs/{}", filename);
        let file_size = std::fs::metadata(&new_path).unwrap().len();
        found_files.push((file_size, new_path));
    }
    found_files.sort();
    for i in found_files {
        print!("{:?}\n", i);
    }

    Ok(())
}
