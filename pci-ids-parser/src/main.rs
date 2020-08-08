#[macro_use]
extern crate lazy_static;
extern crate regex;

use regex::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::u16;

fn main() -> std::io::Result<()> {
    let mut results = File::create("pciids")?;

    match File::open("pci.ids") {
        Err(_) => {
            println!("pci.ids file not found");
            println!("wget https://raw.githubusercontent.com/pciutils/pciids/master/pci.ids");
        }

        Ok(mut file) => {
            let mut data = String::new();
            file.read_to_string(&mut data)?;

            lazy_static! {
                static ref GET_VENDOR: Regex = Regex::new(r"^([0-9a-f]{4})  (.*)$").unwrap();
                static ref GET_DEVICE: Regex = Regex::new(r"^\t([0-9a-f]{4})  (.*)$").unwrap();
                static ref GET_SUBDEVICE: Regex =
                    Regex::new(r"^\t\t([0-9a-f]{4}) ([0-9a-f]{4})  (.*)$").unwrap();
            }

            let mut curr_vendor = "FFFFFFFF".to_string();
            let mut curr_vendor_desc = "Not found".to_string();

            let mut curr_device;
            let mut curr_device_desc;

            for line in data.lines() {
                if line.starts_with("#") {
                    // Ignoring comments
                    continue;
                }

                for cap in GET_VENDOR.captures_iter(line) {
                    curr_vendor = cap[1].to_string().replace("\"", "'").replace("\\", "\\\\");
                    curr_vendor_desc = cap[2].to_string().replace("\"", "'").replace("\\", "\\\\");
                }

                for cap in GET_DEVICE.captures_iter(line) {
                    curr_device = cap[1].to_string().replace("\"", "'").replace("\\", "\\\\");
                    curr_device_desc = cap[2].to_string().replace("\"", "'").replace("\\", "\\\\");
                    results.write_all(
                        format!(
                            "({:#x}, {:#x}) => \"{}:{}\",\n",
                            u16::from_str_radix(&curr_vendor, 16).unwrap(),
                            u16::from_str_radix(&curr_device, 16).unwrap(),
                            curr_vendor_desc,
                            curr_device_desc
                        )
                        .as_bytes(),
                    )?;
                }

                for cap in GET_SUBDEVICE.captures_iter(line) {
                    let _subdevice_id = &cap[2];
                    let _subdevice_descr = &cap[3];
                }
            }
        }
    }

    println!("Results written to pciids");
    Ok(())
}
