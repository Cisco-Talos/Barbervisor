#![no_std]

extern crate cpu;

/* COM devices
 *
 * (address, is_present, is_active)
 *
 * address    - I/O address of port
 * is_present - Set if scratchpad and loopback tests pass
 * is_active  - Set if ??? is set
 * is_init    - Set if port has been probed
 */

struct ComStruct {
    pub address: u16,
    pub is_present: bool,
    pub is_active: bool,
    pub is_init: bool,
}

static mut COM1: ComStruct = ComStruct {
    address: 0x3f8,
    is_present: false,
    is_active: false,
    is_init: false,
};
static mut COM2: ComStruct = ComStruct {
    address: 0x2f8,
    is_present: false,
    is_active: false,
    is_init: false,
};
static mut COM3: ComStruct = ComStruct {
    address: 0x3e8,
    is_present: false,
    is_active: false,
    is_init: false,
};
static mut COM4: ComStruct = ComStruct {
    address: 0x2e8,
    is_present: false,
    is_active: false,
    is_init: false,
};

#[macro_export]
macro_rules! print {
    ( $($arg:tt)* ) => ({
        use core::fmt::Write;
        let _ = write!(&mut $crate::Writer, $($arg)*);
    })
}

/// Writer implementation used by the `print!` macro
pub struct Writer;

impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write(s);
        Ok(())
    }
}

unsafe fn init(port: &mut ComStruct) {
    /* Set port to initialized state */
    port.is_active = true;

    /* Set scratchpad to contain 0x41, and check if it reads it back */
    cpu::out8(port.address + 7, 0x41);
    if cpu::in8(port.address + 7) != 0x41 {
        port.is_present = false;
        port.is_active = false;
        return;
    }

    /* Mark port as present */
    port.is_present = true;

    /* Disable all interrupts */
    cpu::out8(port.address + 1, 0);

    /* Set DLAB */
    cpu::out8(port.address + 3, 0x80);

    /* Write low divisor byte */
    cpu::out8(port.address + 0, 1);

    /* Write high divisor byte */
    cpu::out8(port.address + 1, 0);

    /* Clear DLAB, set word length to 8 bits, one stop bit, no parity */
    cpu::out8(port.address + 3, 3);

    /* Disable FIFOs entirely */
    cpu::out8(port.address + 2, 0xc7);

    /* Set RTS and DTR */
    cpu::out8(port.address + 4, 0x0b);

    /* If clear to send, data set ready, and data carrier detect are set
     * mark this port as active!
     */
    if cpu::in8(port.address + 6) & 0b10110000 == 0b10110000 {
        /* Mark port as active */
        port.is_active = true;
    }
}

/// Invoke a closure on each port which has been identified
fn for_each_port<F: FnMut(u16)>(mut func: F) {
    unsafe {
        /* If ports are not initialized, initialize them */
        if !COM1.is_active {
            init(&mut COM1)
        }
        if !COM2.is_active {
            init(&mut COM2)
        }
        if !COM3.is_active {
            init(&mut COM3)
        }
        if !COM4.is_active {
            init(&mut COM4)
        }

        if COM1.is_present {
            func(COM1.address)
        }
        if COM2.is_present {
            func(COM2.address)
        }
        if COM3.is_present {
            func(COM3.address)
        }
        if COM4.is_present {
            func(COM4.address)
        }
    }
}

/// Write a byte to the serial port data port
pub fn write_byte(byte: u8) {
    /* LF implies CR+LF */
    if byte == b'\n' {
        write_byte(b'\r');
    }

    for_each_port(|port| unsafe {
        while (cpu::in8(port + 5) & 0x20) == 0 {}
        cpu::out8(port, byte);
    });
}

/// Write bytes to the serial device
pub fn write_bytes(data: &[u8]) {
    for &byte in data {
        write_byte(byte);
    }
}

/// Write a string to the serial device as UTF-8 bytes
pub fn write(string: &str) {
    write_bytes(string.as_bytes());
}

/// Returns Some(byte) if a byte is present on the serial port, otherwise
/// returns None
pub fn probe_byte() -> Option<u8> {
    let mut byte = None;

    for_each_port(|port| unsafe {
        if byte.is_none() && (cpu::in8(port + 5) & 1) != 0 {
            byte = Some(cpu::in8(port));
        }
    });

    byte
}
