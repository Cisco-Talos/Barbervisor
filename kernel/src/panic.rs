use crate::vga_print;
use core::panic::PanicInfo;
use cpu;

/// Panic implementation
#[panic_handler]
#[no_mangle]
pub fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        vga_print!("!!! PANIC !!! {}:{}\n", location.file(), location.line(),);
    } else {
        vga_print!("!!! PANIC !!! Panic with no location info\n");
    }

    if let Some(&args) = info.message() {
        vga_print!("{}", args);
        // use core::fmt::write;
        // let _ = write(&mut crate::Writer, args);
        vga_print!("\n");
    } else {
        vga_print!("No arguments\n");
    }

    cpu::halt();
}
