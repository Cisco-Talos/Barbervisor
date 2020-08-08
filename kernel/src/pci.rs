use crate::print;
use cpuio::Port;

const CONFIG_ADDRESS: u16 = 0xcf8;
const CONFIG_DATA: u16 = 0xcfc;

const INVALID_VENDOR: u16 = 0xffff;

const OFFSET_VENDOR_ID: u8 = 0x0;
const OFFSET_DEVICE_ID: u8 = 0x2;
const OFFSET_COMMAND: u8 = 0x4;
const OFFSET_STATUS: u8 = 0x6;
const OFFSET_REVISION_ID: u8 = 0x8;
const OFFSET_PROG_IF: u8 = 0x9;
const OFFSET_SUBCLASS: u8 = 0xa;
const OFFSET_CLASS_CODE: u8 = 0xb;
const OFFSET_CACHE_LINE_SIZE: u8 = 0xc;
const OFFSET_LATENCY_TIMER: u8 = 0xd;
const OFFSET_HEADER_TYPE: u8 = 0xe;
const OFFSET_BUILT_IN_SELF_TEST: u8 = 0xf;
const OFFSET_CARDBUS_BASE: u8 = 0x10;
const OFFSET_CAPABILITIES_LIST: u8 = 0x14;
const OFFSET_SECONDARY_STATUS: u8 = 0x16;
const OFFSET_PCI_BUS_NUMBER: u8 = 0x18;
const OFFSET_CARDBUS_BUS_NUMBER: u8 = 0x19;
const OFFSET_SUBORDINATE_BUS_NUMBER: u8 = 0x1a;
const OFFSET_CARDBUS_LATENCY_TIMER: u8 = 0x1b;
const OFFSET_MEMORY_BASE_ADDRESS_0: u8 = 0x1c;
const OFFSET_MEMORY_LIMIT_0: u8 = 0x20;
const OFFSET_MEMORY_BASE_ADDRESS_1: u8 = 0x24;
const OFFSET_MEMORY_LIMIT_1: u8 = 0x28;
const OFFSET_IO_BASE_ADDRESS_0: u8 = 0x2c;
const OFFSET_IO_LIMIT_0: u8 = 0x30;
const OFFSET_IO_BASE_ADDRESS_1: u8 = 0x34;
const OFFSET_IO_LIMIT_1: u8 = 0x38;
const OFFSET_INTERRUPT_LINE: u8 = 0x3c;
const OFFSET_INTERRUPT_PIN: u8 = 0x3d;
const OFFSET_BRIDGE_CONTROL: u8 = 0x3e;
const OFFSET_SUBSYSTEM_DEVICE_ID: u8 = 0x40;
const OFFSET_SUBSYSTEM_VENDOR_ID: u8 = 0x42;
const OFFSET_PC_CARD_LEGACY_BASE_ADDRESS: u8 = 0x44;

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum DeviceState {
    Unknown,
    Invalid,
    Valid(u16),
}

impl core::fmt::Debug for DeviceState {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            DeviceState::Unknown => write!(f, "Unknown"),
            DeviceState::Invalid => write!(f, "Invalid"),
            DeviceState::Valid(x) => write!(f, "{:x}", x),
        }
    }
}

#[derive(Copy, Clone)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub func: u8,
    pub vendor_id: DeviceState,
    pub device_id: DeviceState,
    pub bars: [Bar; 6],
}

impl core::fmt::Debug for PciDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "Pci(bus: {} device: {} func: {} vendor_id: {:?} device_id: {:?} bars: {:?})",
            self.bus, self.device, self.func, self.vendor_id, self.device_id, self.bars
        )
    }
}

impl PciDevice {
    fn new(bus: u8, device: u8, func: u8) -> PciDevice {
        PciDevice {
            bus,
            device,
            func,
            vendor_id: DeviceState::Unknown,
            device_id: DeviceState::Unknown,
            bars: [Bar {
                address: 0xffffffff,
                bar_type: BarType::Unused,
            }; 6],
        }
    }

    pub fn to_addr(&self, offset: u8) -> u32 {
        (1 << 31) as u32             /* Enable bit */
            | (self.bus as u32) << 16    /* Bus in bits 23-16 */
            | (self.device as u32) << 11 /* device in bits 15-11 */
            | (self.func as u32) << 8 /* function in bits 10-8 */
            | (offset & 0xfc) as u32 /* offset in bits 7-0 */
    }

    /// Read the u32 for a given offset
    pub fn read_u32(&self, offset: u8) -> u32 {
        let mut config_address_port: Port<u32> = unsafe { Port::new(CONFIG_ADDRESS) };
        config_address_port.write(self.to_addr(offset));

        let mut config_data_port: Port<u32> = unsafe { Port::new(CONFIG_DATA) };
        config_data_port.read()
    }

    /// Read the u16 for a given offset
    pub fn read_u16(&self, offset: u8) -> u16 {
        // offset 0 -> shift 0  | offset 1 -> shift 8
        // offset 2 -> shift 16 | offset 3 -> shift 24
        // offset 4 -> shift 0  | ...ect
        let bitshift = (offset % 4) * 8;
        (self.read_u32(offset) >> bitshift) as u16
    }

    /// Read the u8 for a given offset
    pub fn read_u8(&self, offset: u8) -> u8 {
        // offset 0 -> shift 0  | offset 1 -> shift 8
        // offset 2 -> shift 16 | offset 3 -> shift 24
        // offset 4 -> shift 0  | ...ect
        let bitshift = (offset % 4) * 8;
        (self.read_u32(offset) >> bitshift) as u8
    }

    /// Read the u32 for a given offset
    pub fn write_u32(&self, offset: u8, value: u32) {
        let mut config_address_port: Port<u32> = unsafe { Port::new(CONFIG_ADDRESS) };
        config_address_port.write(self.to_addr(offset));

        let mut config_data_port: Port<u32> = unsafe { Port::new(CONFIG_DATA) };
        config_data_port.write(value);
    }

    /// Write the u16 for a given offset
    pub fn write_u16(&self, offset: u8, value: u16) {
        let mut config_address_port: Port<u32> = unsafe { Port::new(CONFIG_ADDRESS) };
        config_address_port.write(self.to_addr(offset));

        let mut config_data_port: Port<u16> = unsafe { Port::new(CONFIG_DATA) };
        config_data_port.write(value);
    }

    /// Write the u8 for a given offset
    pub fn write_u8(&self, offset: u8, value: u8) {
        let mut config_address_port: Port<u32> = unsafe { Port::new(CONFIG_ADDRESS) };
        config_address_port.write(self.to_addr(offset));

        let mut config_data_port: Port<u8> = unsafe { Port::new(CONFIG_DATA) };
        config_data_port.write(value);
    }

    /// Read the COMMAND register into CommandFlags
    pub fn read_command(&self) -> CommandFlags {
        CommandFlags::from_bits_truncate(self.read_u16(OFFSET_COMMAND))
    }

    /// Write a new command to the COMMAND register.
    /// Overwrites the COMMAND register with the new given value
    pub fn write_command(&self, value: CommandFlags) {
        self.write_u16(OFFSET_COMMAND, value.bits());
    }

    /// Insert new flags into the COMMAND register.
    /// Keeps the original COMMAND register in tact, while adding new fields
    pub fn insert_command(&self, value: CommandFlags) {
        let mut curr_command = self.read_command();
        curr_command.insert(value);
        self.write_command(curr_command);
    }

    /// Enables Bus Master bit in the COMMAND register
    pub fn enable_bus_master(&self) {
        self.insert_command(CommandFlags::BUS_MASTER);
    }

    /// Return the Vender ID of this Device  if it exists.
    /// Return None if invalid vendor ID
    pub fn vendor_id(&mut self) -> Option<u16> {
        if self.vendor_id == DeviceState::Unknown {
            // Vendor ID is offset 0 per PCI
            let register_0 = self.read_u32(0);

            let vendor_id = (register_0 & 0xffff) as u16;
            let device_id = (register_0 >> 16) as u16;

            match vendor_id {
                INVALID_VENDOR => self.vendor_id = DeviceState::Invalid,
                _ => {
                    // If vendor is valid, populate the device ID as well
                    self.vendor_id = DeviceState::Valid(vendor_id);
                    self.device_id = DeviceState::Valid(device_id);
                }
            }
        }

        assert!(self.vendor_id != DeviceState::Unknown);

        match self.vendor_id {
            DeviceState::Valid(x) => Some(x),
            DeviceState::Invalid => None,
            DeviceState::Unknown => panic!("Unable to set vendor_id"),
        }
    }

    /// Return the Device ID for this device
    pub fn device_id(&mut self) -> u16 {
        assert!(self.device_id != DeviceState::Unknown);

        match self.device_id {
            DeviceState::Valid(x) => x,
            DeviceState::Invalid => panic!("Invalid Device ID?!.. should never be set"),
            DeviceState::Unknown => panic!("Unable to set device_id"),
        }
    }

    /// Initializes the rest of this device.
    /// Currently, initializes the 6 Base Address Registers for this device
    pub fn init(&mut self) {
        self.read_bars();
    }

    pub fn read_bars(&mut self) {
        let mut bar_index = 0;
        let mut curr_bar_offset = 0x10;

        // Can't use an iterator here since the 64 bit Memory Space option
        // needs to look ahead by one register.

        while curr_bar_offset <= 0x24 {
            let bar = self.read_u32(curr_bar_offset);

            if bar == 0 {
                curr_bar_offset += 4;
                bar_index += 1;
                continue;
            }

            // Create BAR struct based on the Type and Address
            let curr_bar = match bar & 1 {
                0 => {
                    // Memory Space BAR
                    // Next two bits describe the Memory Space type
                    match bar >> 1 & 3 {
                        0 => Bar {
                            address: bar as u64 & 0xffff_fff0,
                            bar_type: BarType::MemSpace32,
                        },
                        2 => {
                            // Ensure there is at least one additional bar register to read form
                            assert!(curr_bar_offset + 4 <= 0x24);
                            let high_addr = self.read_u32(curr_bar_offset + 4);
                            let low_addr = bar as u64 & 0xffff_fff0;
                            let address = (high_addr as u64) << 32 | low_addr as u64;
                            Bar {
                                address: address,
                                bar_type: BarType::MemSpace64,
                            }
                        }
                        _ => panic!("Unknown bar type found: {}", bar >> 1 & 3),
                    }
                }
                1 => {
                    // IO Space BAR
                    Bar {
                        address: bar as u64 & 0xffff_fffc,
                        bar_type: BarType::IoSpace,
                    }
                }
                _ => panic!("Unknown bar type found"),
            };

            // Insert the bar into the bars array
            self.bars[bar_index] = curr_bar;

            // Increment offsets
            curr_bar_offset += 4;
            bar_index += 1;
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum BarType {
    Unused,
    MemSpace32,
    MemSpace64,
    IoSpace,
}

/// Struct for Base Address Registers
#[derive(Copy, Clone)]
pub struct Bar {
    pub address: u64,
    pub bar_type: BarType,
}

impl core::fmt::Debug for Bar {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}: {:?}", self.address, self.bar_type)
    }
}

fn check_device(bus: u8, device: u8, function: u8) {
    let mut curr_pci = PciDevice::new(bus, device, function);
    if curr_pci.vendor_id().is_none() || curr_pci.vendor_id() != Some(0x8086) {
        return;
    }

    curr_pci.init();
    print!("Found PCI: {:?}\n", curr_pci);
}

pub fn print_all_devices() {
    for curr_bus in 0..=255 {
        for curr_device in 0..32 {
            for curr_func in 0..8 {
                check_device(curr_bus, curr_device, curr_func);
            }
        }
    }
}

pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    for curr_bus in 0..=255 {
        for curr_device in 0..0x20 {
            for curr_func in 0..8 {
                let mut curr_pci = PciDevice::new(curr_bus, curr_device, curr_func);
                if curr_pci.vendor_id().is_none() {
                    continue;
                }

                if curr_pci.vendor_id() == Some(vendor_id) && curr_pci.device_id() == device_id {
                    curr_pci.init();
                    return Some(curr_pci);
                }
            }
        }
    }

    None
}

bitflags! {
    pub struct CommandFlags: u16 {
        /// If set to 1 the device can respond to I/O Space accesses; otherwise, the device's response is disabled.
        const IO_SPACE = 1 << 0;

        /// If set to 1 the device can respond to Memory Space accesses; otherwise, the device's response is disabled.
        const MEMORY_SPACE = 1 << 1;

        /// If set to 1 the device can behave as a bus master; otherwise, the device can not generate PCI accesses.
        const BUS_MASTER = 1 << 2;

        /// If set to 1 the device can monitor Special Cycle operations; otherwise, the device will ignore them.
        const SPECIAL_CYCLES = 1 << 3;

        /// If set to 1 the device can generate the Memory Write and Invalidate command; otherwise, the Memory Write command must be used.
        const MEMORY_WRITE_INVALIDATE = 1 << 4;

        ///  If set to 1 the device does not respond to palette register writes and will snoop the data;
        ///  otherwise, the device will trate palette write accesses like all other accesses.
        const VGA_PALLETTE_SNOOP = 1 << 5;

        /// If set to 1 the device will take its normal action when a parity error is detected;
        /// otherwise, when an error is detected, the device will set bit 15 of the Status register
        /// (Detected Parity Error Status Bit), but will not assert the PERR# (Parity Error) pin and
        /// will continue operation as normal.
        const PARITY_ERROR_RESPONSE = 1 << 6;

        /// If set to 1 the SERR# driver is enabled; otherwise, the driver is disabled.
        const SERR_ENABLE = 1 << 8;

        ///  If set to 1 indicates a device is allowed to generate fast back-to-back transactions;
        ///  otherwise, fast back-to-back transactions are only allowed to the same agent.
        const FAST_BACK_TO_BACK_ENABLE = 1 << 7;

        /// If set to 1 the assertion of the devices INTx# signal is disabled;
        /// otherwise, assertion of the signal is enabled.
        const INTERRUPT_DISABLE = 1 << 8;
    }
}
