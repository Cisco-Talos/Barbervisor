//! Various utilities like hexdump for debugging
use crate::print;
use crate::KernelPhysical;

/// Display the given physical address address in a hexdump format
///
/// Example:
///
/// hexdump(0x106a1000, 0x40);
///
/// 0x106a1000: 48 ff c0 48 ff c3 48 ff c1 48 ff c2 48 ff c6 48 : H..H..H..H..H..H
/// 0x106a1010: ff c7 49 ff c0 49 ff c1 49 ff c2 49 ff c3 49 ff : ..I..I..I..I..I.
/// 0x106a1020: c4 49 ff c5 49 ff c6 49 ff c7 48 ff c4 48 ff c5 : .I..I..I..H..H..
/// 0x106a1030: 48 ff c8 0f 01 c1 00 00 00 00 00 00 00 00 00 00 : H...............
pub fn hexdump(addr: u64, n: u64) {
    let curr_addr = addr;

    for i in (0..n).step_by(0x10) {
        print!("{:#x}: ", curr_addr + i);

        for x in i..i + 0x10 {
            unsafe {
                print!("{:0>2x} ", *((curr_addr + x) as *mut u8));
            }
        }

        print!("\n");
    }
}

/// Hexdump for &[u8]
pub fn dump(data: &[u8]) {
    for i in (0..data.len()).step_by(0x10) {
        let max = if i + 0x10 > data.len() {
            data.len()
        } else {
            i + 0x10
        };

        for x in i..max {
            print!("{:0>2x} ", data[x]);
        }

        // Padding in case the slice isn't a multiple of 0x10
        if max % 16 != 0 {
            for _ in 0..(0x10 - (max % 16)) {
                print!("00 ");
            }
        }

        print!(": ");

        for x in i..max {
            let c = data[x];
            match c {
                (0x20..0x7e) => print!("{}", c as char),
                _ => print!("."),
            }
        }

        // Padding in case the slice isn't a multiple of 0x10
        if max % 16 != 0 {
            for _ in 0..(0x10 - max % 16) {
                print!(".");
            }
        }

        print!("\n");
    }
}

/// Memcpy with C's arguments
#[inline(always)]
pub fn memcpy(dest: *mut u8, src: *const u8, n: usize) {
    unsafe {
        core::intrinsics::copy_nonoverlapping(src, dest, n);
    }
}

/// Memcpy with C's arguments
pub fn memcpy_page(dest: KernelPhysical, src: *const [u8; 4096]) {
    assert!(dest.0 & 0xfff == 0);

    unsafe {
        core::intrinsics::copy_nonoverlapping(src, dest.0 as *mut [u8; 4096], 4096);
    }
}

/// Memcpy with slice
pub fn memcpy_slice(dest: *mut u8, src: &[u8]) {
    memcpy(dest, src.as_ptr(), src.len());
}
