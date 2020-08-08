use std::collections::{HashMap, HashSet};
use std::vec::Vec;
use std::path::{Path, PathBuf};
use noodle::Deserialize;

#[derive(Debug)]
pub struct Coverage {
    /// (Input name, vector of addresses for coverage)
    pub inputs: HashMap<String, HashMap<u64, u64>>,

    /// All possible addresses currently seen by these inputs
    pub seen_coverage: HashSet<u64>,
   
    /// Mapping of addresses to all inputs that have seen that address
    ///
    /// (Address, Set of all inputs that have hit this address)
    pub total_coverage: HashMap<u64, HashSet<String>>
}

impl Coverage {
    /// Populates the coverage struct from ./project/inputs and ./project/coverages
    pub fn from_current_dir() -> Coverage {
        let mut res = Coverage {
            inputs: HashMap::new(),
            seen_coverage: HashSet::new(),
            total_coverage: HashMap::new(),
        };

        if !Path::new("./project").exists() {
            std::fs::create_dir("./project").expect("Unable to create ./project dir");    
        }

        if !Path::new("./project/inputs").exists() {
            std::fs::create_dir("./project/inputs").expect("Unable to create ./project/inputs dir");    
        }

        if !Path::new("./project/coverages").exists() {
            std::fs::create_dir("./project/coverages").expect("Unable to create ./project/coverages dir");    
        }

        for input in Path::new("./project/inputs").read_dir().expect("Couldn't open ./project/inputs") {
            if let Ok(entry) = input {
                let path = entry.path();
                let filename = path.file_name().unwrap().to_str().unwrap();
                let mut cov_path = PathBuf::new();
                cov_path.push(".");
                cov_path.push("project");
                cov_path.push("coverages");
                cov_path.push(filename);
                cov_path.set_extension("coverage");
                if cov_path.as_path().exists() {
                    let data = std::fs::read(&cov_path).expect(&format!("Unable to read {:?}", cov_path));
                    let cov = <Vec<[u64; 2]> as Deserialize>::deserialize(&mut data.as_slice()).unwrap();
                    res.insert(String::from(cov_path.to_str().unwrap()), cov);
                } else {
                    print!("Coverage {:?} not found\n", cov_path);
                }
            }
        }

        print!("Init Coverage: inputs {} total {}\n", res.inputs.keys().len(), res.total_coverage.len()); 
        // print!("{:#x?}\n", res);
        res.minset();
        res

    }

    pub fn insert(&mut self, name: String, input: Vec<[u64; 2]>) {
        let mut new_coverage = false;
        // Check if this input should be added to the database
        // For now, only adding inputs that add strictly new coverage to the database
        let mut curr_cov = HashMap::new();
        for entry in &input {
            let addr = entry[0];
            let _curr_hit_count = entry[1];
            let count = curr_cov.entry(addr).or_insert(0);
            *count += 1;

            // Add the current entry 
            let found_in = self.total_coverage.entry(addr).or_insert(HashSet::new());
            found_in.insert(name.clone());

            if self.seen_coverage.insert(addr) {
                new_coverage = true;
            }
        }

        if new_coverage {
            self.inputs.insert(name, curr_cov);
        }
    }

    pub fn minset(&mut self) -> Vec<String> {
        let mut total_coverage: HashMap<u64, HashSet<String>> = self.total_coverage.clone();
        let mut files_coverage: HashMap<String, HashMap<u64, u64>> = self.inputs.clone();

        print!("In minset.. ");
        loop {
            if total_coverage.keys().len() == 0 {
                // println!("DONE");
                break;
            }

            let mut single_file: Option<String> = None;
            for (_symbol, files) in &total_coverage {
                if files.len() == 1 {
                    // single_file = Some(files[0].clone());
                    single_file = Some(files.iter().next().unwrap().to_string());
                    break;
                }
            }

            if single_file.is_none() {
                // Choose the file with the most coverage currently
                let mut files_by_coverage_count = files_coverage
                    .iter()
                    .map(|(k, v)| (v.len(), k))
                    .collect::<Vec<_>>();
                files_by_coverage_count.sort();
                single_file = Some(files_by_coverage_count.last().unwrap().1.to_string());
            }

            if let Some(curr_file) = single_file {
                // println!("Removing entries in {:?}", curr_file);
                for symbol in files_coverage.get(&curr_file).unwrap().keys() {
                    total_coverage.remove(symbol);
                }
                files_coverage.remove(&curr_file);
            } else {
                println!("Did not find a file to remove entries..");
                break;
            }
        }

        if files_coverage.keys().len() > 0 {
            print!("inputs after: {:?}\n", files_coverage.keys().len());
        }
        print!("out minset\n");
        Vec::new()
    }
}
