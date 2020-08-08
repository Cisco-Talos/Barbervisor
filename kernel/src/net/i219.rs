#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
use crate::dbg;
use crate::mm;
use crate::net::*;
use crate::pci::{self, BarType, PciDevice};
use crate::time::sleep;
use crate::tools::*;

use packets::ethernet::{Frame as EthernetFrame, Protocol as EthernetProtocol};
use spin::Mutex;

const NUM_TX_DESCRIPTORS: usize = 128;
const NUM_RX_DESCRIPTORS: usize = 128;

impl NetworkDriver for I219 {
    fn bar_type(&self) -> BarType {
        self.pci.bars[0].bar_type
    }

    fn mem_base(&self) -> u64 {
        self.pci.bars[0].address
    }

    fn send_packet(&self, payload: &[u8]) {
        let curr_tail = self.read_u32(TX_DESCRIPTOR_TAIL);

        let mut tx_descriptor =
            (self.tx_buffers_addr + (curr_tail as u64 * 16)) as *mut TxDescriptor;

        unsafe {
            memcpy(
                (*tx_descriptor).address as *mut u8,
                payload.as_ptr(),
                payload.len(),
            );

            (*tx_descriptor).length = payload.len() as u16;
            (*tx_descriptor).status = TxDescStatus::empty().bits();

            (*tx_descriptor).command = (
                TxDescCommand::END_OF_PACKET
                | TxDescCommand::INSERT_FCS
                | TxDescCommand::REPORT_STATUS)
                .bits();
        }

        // Increment the tail index for the next transmit
        let new_tail = (curr_tail + 1) % NUM_TX_DESCRIPTORS as u32;

        self.write_u32(TX_DESCRIPTOR_TAIL, new_tail);

        unsafe {
            loop {
                // Wait for 10 seconds for the packet to be sent
                for _ in 0..100 {
                    if ((*tx_descriptor).status & 0xff) > 0 {
                        return;
                    }
                    sleep(500);
                }

                panic!("Unable to send packet.. timeout.");
            }
        }
    }

    fn next_packet(&self) -> EthernetFrame<&[u8]> {
        let mut i = self.read_u32(RX_DESCRIPTOR_TAIL);

        loop {
            // Select the current descriptor by index
            let mut rx_descriptor = (self.rx_buffers_addr + (i as u64 * 16)) as *mut RxDescriptor;

            unsafe {
                // Only are if the Rx Descriptor has something for us
                if (*rx_descriptor).status > 0 {
                    let packet = core::slice::from_raw_parts(
                        (*rx_descriptor).address as *mut u8,
                        (*rx_descriptor).length as usize,
                    );

                    let ethernet = EthernetFrame::new_unchecked(packet);

                    // Reset Rx Descriptor for more use
                    (*rx_descriptor).status = 0;

                    // Filter packets based on our MAC address
                    if ethernet.src_addr() == DESKTOP_MAC_ADDR
                        && ethernet.dst_addr() == LAPTOP_MAC_ADDR
                        && ethernet.protocol() == EthernetProtocol::Ipv4
                    {
                        // Cycle around the descriptors
                        i = (i + 1) % (NUM_RX_DESCRIPTORS as u32);

                        // Let the NIC know this is the new tail
                        self.write_u32(RX_DESCRIPTOR_TAIL, i as u32);

                        // hexdump((*rx_descriptor).address, (*rx_descriptor).length as u64);
                        return ethernet;
                    }

                    if ethernet.src_addr() == DESKTOP_MAC_ADDR
                        && ethernet.protocol() == EthernetProtocol::Arp
                    {
                        // TODO: Make an actual ARP packet in packets
                        let payload = [
                            0xb4, 0x96, 0x91, 0xec, 0xdf, 0xb6, 0xa0, 0x36, 0x9f, 0x21, 0x4a, 0x87,
                            0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x50, 0x7b,
                            0x9d, 0xb9, 0xce, 0x28, 0xc0, 0xa8, 0x01, 0xc8, 0xb4, 0x96, 0x91, 0x39,
                            0x9d, 0x09, 0xc0, 0xa8, 0x01, 0x4d,
                        ];

                        self.send_packet(&payload);
                    }
                }
            }

            // Cycle around the descriptors
            i = (i + 1) % (NUM_RX_DESCRIPTORS as u32);
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct TxDescriptor {
    /// Buffer address of this Tx Descriptor
    address: u64,
    length: u16,
    checksum_offset: u8,
    command: u8,
    status: u8,
    checksum_start: u8,
    special: u16,
}

bitflags! {
    pub struct TxDescCommand: u8 {
        const END_OF_PACKET = 1 << 0;
        const INSERT_FCS = 1 << 1;
        const INSERT_CHECKSUM = 1 << 2;
        const REPORT_STATUS = 1 << 3;
        const EXTENSION = 1 << 5;
        const VLAN_PACKET = 1 << 6;
        const INTERRUPT_DELAY = 1 << 7;
    }
}

impl Default for TxDescCommand {
    fn default() -> Self {
        TxDescCommand::empty()
    }
}

bitflags! {
    pub struct TxDescStatus: u8 {
        const DESCRIPTOR_DONE = 1 << 0;
        const EXCESS_COLLISIONS = 1 << 1;
        const LATE_COLLISION = 1 << 2;
    }
}

impl Default for TxDescStatus {
    fn default() -> Self {
        TxDescStatus::empty()
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct RxDescriptor {
    /// Buffer address of this Rx Descriptor
    address: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

bitflags! {
    pub struct RxDescStatus: u8 {
        const END_OF_PACKET = 1 << 0;
        const IGNORE_CHECKSUM = 1 << 1;
        const IS_802_1Q = 1 << 2;
        const UDP_CHECKSUM_CALCULATED = 1 << 3;
        const TCP_CHECKSUM_CALCULATED = 1 << 4;
        const IPV4_CHECKSUM_CALCULATED = 1 << 5;
        const PASSED_IN_EXACT_FILTER = 1 << 6;
    }
}

impl Default for RxDescStatus {
    fn default() -> Self {
        RxDescStatus::empty()
    }
}

bitflags! {
    pub struct RxDescError: u8 {
        const CRC_ERROR = 1 << 0;
        const SYMBOL_ERROR = 1 << 1;
        const SEQUENCE_ERROR = 1 << 2;
        const TCP_UDP_CHECKSUM_ERROR = 1 << 3;
        const IPV4_CHECKSUM_ERROR = 1 << 4;
        const RX_DATA_ERROR = 1 << 5;
    }
}

impl Default for RxDescError {
    fn default() -> Self {
        RxDescError::empty()
    }
}

#[derive(Debug)]
pub struct I219 {
    pci: PciDevice,
    tx_buffers_addr: u64,
    rx_buffers_addr: u64,
    pub mac: [u8; 6],
}

impl I219 {
    pub fn new(pci: PciDevice) -> I219 {
        let mut res = I219 {
            pci: pci,
            mac: [0xff; 6],
            tx_buffers_addr: 0,
            rx_buffers_addr: 0,
        };

        res.init();
        res
    }

    fn init(&mut self) {
        self.set_mac_address();
        self.pci.enable_bus_master();
        self.reset_nic();
        self.enable_interrupts();
        self.rxinit();
        self.txinit();
        print!("I219 done init!\n");
    }

    fn set_mac_address(&mut self) {
        const MAC_ADDRESS: u16 = 0x5400;
        for i in 0..6 {
            let result = self.read_u8(MAC_ADDRESS + i);
            self.mac[i as usize] = result;
        }

        dbg!("Mac: {:?}\n", self.mac);
    }

    fn reset_nic(&mut self) {
        dbg!("Writing 0 to status\n");
        self.write_u32(DEVICE_STATUS, 0);

        dbg!("Clearing interrupts\n");
        self.write_u32(INTERRUPT_CLEAR, 0xffff_ffff);

        dbg!("Issue full reset\n");
        let mut curr_device_control = DeviceControls::from_u32(self.read_u32(DEVICE_CONTROL));
        curr_device_control.host_software_reset = true;
        curr_device_control.duplex = Duplex::Full;
        self.write_u32(DEVICE_CONTROL, curr_device_control.bits());

        sleep(1000);

        dbg!("Waiting for reset pin to clear\n");
        loop {
            let curr_device_control = DeviceControls::from_u32(self.read_u32(DEVICE_CONTROL));
            if !curr_device_control.host_software_reset {
                break;
            }
            print!("Sleeping for host software reset\n");
            sleep(1000);
        }

        dbg!("Clearing interrupts after reset\n");
        self.write_u32(INTERRUPT_CLEAR, 0xffff_ffff);

        dbg!("Enabling Transmit and Receive Flow Control\n");
        let mut curr_device_control = DeviceControls::from_u32(self.read_u32(DEVICE_CONTROL));
        curr_device_control.receive_flow_control = true;
        curr_device_control.transmit_flow_control = true;
        curr_device_control.duplex = Duplex::Full;
        self.write_u32(DEVICE_CONTROL, curr_device_control.bits());

        let curr_device_control = DeviceControls::from_u32(self.read_u32(DEVICE_CONTROL));
        dbg!("Device Control\n{:?}\n", curr_device_control);

        dbg!("Clear Multicast Table Array\n");
        for i in (0..0x80).step_by(4) {
            self.write_u32(MULTICAST_TABLE_ARRAY + i, 0);
        }
    }

    fn enable_interrupts(&mut self) {
        self.write_u32(INTERRUPT_SET, 0x1f6dc as u32);
        self.write_u32(INTERRUPT_SET, 0xff & !4);
        self.read_u32(INTERRUPT_READ);
    }

    fn rxinit(&mut self) {
        self.rx_buffers_addr = mm::alloc_page()
            .expect("Unable to alloc page for tx buffers")
            .as_ptr() as u64;

        unsafe {
            for i in 0..NUM_RX_DESCRIPTORS {
                let mut rx_descriptor =
                    (self.rx_buffers_addr + (i as u64 * 16)) as *mut RxDescriptor;

                // Allocate 0x3000 bytes for each buffer. 0x2000 + 16 is needed, just going to use 3
                // pages each
                (*rx_descriptor).address = mm::alloc_page()
                    .expect("Unable to alloc page for rxinit")
                    .as_ptr() as u64;

                let p2 = mm::alloc_page(); // Alloc page 2
                assert!(p2.unwrap() as *const _ as u64 - 0x1000 == (*rx_descriptor).address);
                let p3 = mm::alloc_page(); // Alloc page 3
                assert!(p3.unwrap() as *const _ as u64 - 0x2000 == (*rx_descriptor).address);

                (*rx_descriptor).status = (RxDescStatus::empty()).bits();
            }
        }

        self.write_u32(
            RX_DESCRIPTOR_LOW,
            (self.rx_buffers_addr & 0xffff_ffff) as u32,
        );
        self.write_u32(RX_DESCRIPTOR_HIGH, (self.rx_buffers_addr >> 32) as u32);

        assert!(core::mem::size_of::<RxDescriptor>() == 16);
        self.write_u32(RX_DESCRIPTOR_LENGTH, (NUM_RX_DESCRIPTORS * 16) as u32);

        dbg!("Setting rx head to 0\n");
        self.write_u32(RX_DESCRIPTOR_HEAD, 0);

        dbg!("Setting rx tail to {}\n", NUM_RX_DESCRIPTORS - 1);
        self.write_u32(RX_DESCRIPTOR_TAIL, (NUM_RX_DESCRIPTORS - 1) as u32);

        dbg!("Creating controls\n");
        let controls = RxControlsBuilder::default()
            .enable(true)
            .store_bad_packets(true)
            .unicast_promiscuous(false)
            .multicast_promiscuous(false)
            .long_packet(true)
            .receive_descriptor_minimum_threshold_size(RxThresholdSize::Half)
            .descriptor_type(RxDescriptorType::Legacy)
            .broadcast_accept_mode(false)
            .strip_ethernet_crc(true)
            .buffer_size(8192)
            .build();

        dbg!("RX controls {:?}\n", controls);
        dbg!("RX controls {:b}\n", controls.bits());

        self.write_u32(RX_CONTROL, controls.bits());
    }

    fn txinit(&mut self) {
        self.tx_buffers_addr = mm::alloc_page()
            .expect("Unable to alloc page for tx buffers")
            .as_ptr() as u64;

        unsafe {
            for i in 0..NUM_TX_DESCRIPTORS {
                let mut tx_descriptor =
                    (self.tx_buffers_addr + (i as u64 * 16)) as *mut TxDescriptor;

                let packet_buffer_addr = mm::alloc_page()
                    .expect("Unable to alloc page for packet_buffer")
                    .as_ptr() as u64;

                // Allocate 0x3000 bytes for each buffer. 0x2000 + 16 is needed, just going to use 3 pages each
                // Crude way to alloc 3 pages for our packets
                // Alloc Page 2
                assert!(
                    mm::alloc_page().expect("Bad alloc page").as_ptr() as u64
                        == packet_buffer_addr + 0x1000
                );
                // Alloc Page 3
                assert!(
                    mm::alloc_page().expect("Bad alloc page").as_ptr() as u64
                        == packet_buffer_addr + 0x2000
                );

                // Every descriptor has the same packet buffer
                (*tx_descriptor).address = packet_buffer_addr;
                (*tx_descriptor).command = 0;

                // Signify buffer is avilable for use
                (*tx_descriptor).status = (TxDescStatus::DESCRIPTOR_DONE).bits();
            }
        }

        dbg!("Disabling controls\n");
        let controls = TxControlsBuilder::new()
            .enable(false)
            .pad_short_packets(true)
            .build();

        dbg!("TX controls {:?}\n", controls);
        dbg!("TX controls {:b}\n", controls.bits());

        self.write_u32(TX_CONTROL, controls.bits());

        dbg!("Writing TX descriptor address\n");
        self.write_u32(
            TX_DESCRIPTOR_LOW,
            (self.tx_buffers_addr & 0xffff_ffff) as u32,
        );
        self.write_u32(TX_DESCRIPTOR_HIGH, (self.tx_buffers_addr >> 32) as u32);

        assert!(core::mem::size_of::<TxDescriptor>() == 16);
        self.write_u32(TX_DESCRIPTOR_LENGTH, (NUM_TX_DESCRIPTORS * 16) as u32);

        dbg!("Setting tx head to 0\n");
        self.write_u32(TX_DESCRIPTOR_HEAD, 0);

        dbg!("Setting tx tail to 0\n");
        self.write_u32(TX_DESCRIPTOR_TAIL, 0);

        dbg!("Enabling controls\n");
        let controls = TxControlsBuilder::new()
            .enable(true)
            .pad_short_packets(true)
            .build();

        // TODO:
        // WHEN NOT USING THE i219, BE SURE TO CHECK WHICH CONTROLS ARE NEEDED
        self.write_u32(TX_CONTROL, controls.bits());
    }

    pub fn print_stats(&self) {
        dbg!(
            "total packets transmitted: {}\n",
            self.read_u32(GOOD_PACKETS_TRANSMITTED)
        );
        dbg!(
            "good packets transmitted: {}\n",
            self.read_u32(TOTAL_PACKETS_TRANSMITTED)
        );
        dbg!(
            "multicast packets transmitted: {}\n",
            self.read_u32(MULTICAST_PACKETS_TRANSMITTED)
        );
        dbg!(
            "broadcast packets transmitted: {}\n",
            self.read_u32(BROADCAST_PACKETS_TRANSMITTED)
        );
        dbg!("number interrupts: {}\n", self.read_u32(INTERRUPT_COUNT));
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Duplex {
    Half,
    Full,
}

impl Default for Duplex {
    fn default() -> Self {
        Duplex::Full
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Speed {
    /// 10 Mb/s
    TenMb = 0,
    /// 100 Mb/s
    HundredMb = 1,
    /// 1000 Mb/s
    OneGb = 2,
}

impl Default for Speed {
    fn default() -> Self {
        Speed::OneGb
    }
}

/// Device Controls struct for easy parsing/generating
///
/// Example
///
/// let mut curr_device_control = DeviceControls::from_u32(self.read_u32(DEVICE_CONTROL));
/// curr_device_control.host_software_reset = true;
/// curr_device_control.duplex = Duplex::Full;
/// self.write_u32(DEVICE_CONTROL, curr_device_control.bits());
///
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct DeviceControls {
    duplex: Duplex,

    /// Master Disable.
    /// When set, the LAN Controller blocks new master requests on the PCI device.
    /// Once no master requests are pending by this function, the Master Enable Status bit is cleared.
    master_disable: bool,

    /// Speed selection (SPEED).
    /// These bits may determine the speed configuration and are written by software
    /// after reading the PHY configuration through the MDIO interface.
    /// These signals are ignored when Auto-Speed Detection is enabled.
    /// (00)b – 10Mb/s
    /// (01)b – 100Mb/s
    /// (10)b – 1000Mb/s
    /// (11)b – not used
    speed: Speed,

    /// Force Speed (FRCSPD).
    /// This bit is set when software wants to manually configure the MAC speed settings
    /// according to the SPEED bits above. When using a PHY device, note that the PHY device
    /// must resolve to the same speed configuration or software must manually set it to the
    /// same speed as the MAC. The value is loaded from word 13h in the NVM.
    /// Note that this bit is superseded by the CTRL_EXT.SPD_BYPS bit which has a similar function.
    force_speed: bool,

    /// Force Duplex (FRCDPLX).
    /// When set to 1, software may override the duplex indication from the PHY that is indicated
    /// in the FDX to the MAC. Otherwise, the duplex setting is sampled from the PHY FDX indication
    /// into the MAC on the asserting edge of the PHY LINK signal. When asserted, the CTRL.FD bit sets duplex.
    force_duplex: bool,

    /// When set to 1 this bit provides the SW driver the ability to control the LANPHYPC pin value
    lanphypc_override: bool,

    /// When LANPHYPC override is set to 1 this bit will define the value of the LANPHYPC pin
    lanphypc_value: bool,

    /// LCD Power Down (LCDPD).
    /// When the bit is cleared to ‘0’, the LCD power down setting is controlled by the internal
    /// logic of the LAN controller. When set to ‘1’ and the CTRL_EXT.PHYPDEN is set as well,
    /// the LAN controller sets the external LCD to power down mode using the LANPHYPC
    lcd_power_down: bool,

    /// Host to ME Interrupt (H2MEINT). Setting this bit asserts the Host interrupt to ME. This bit
    /// is self-clearing
    host_to_me: bool,

    /// Host Software Reset (SWRST).
    /// This bit performs a reset to the PCI data path and the relevant shared logic (see ).
    /// Writing 1 initiates the /eset. This bit is self-clearing.
    host_software_reset: bool,

    /// Receive Flow Control Enable (RFCE).
    /// Indicates the device will respond to the reception of flow control packets.
    /// If Auto-Negotiation is enabled, this bit is set to the negotiated duplex value.
    receive_flow_control: bool,

    /// Transmit Flow Control Enable (TFCE).
    /// Indicates the device will transmit flow control packets (XON & XOFF frames) based on
    /// receiver fullness. If Auto-Negotiation is enabled, this bit is set to the negotiated duplex value
    transmit_flow_control: bool,

    /// VLAN Mode Enable (VME).
    /// When set to 1, all packets transmitted from LAN Controller that have VLE set are sent with
    /// an 802.1Q header added to the packet. The contents of the header come from the transmit
    /// descriptor and from the VLAN type register. On receive, VLAN information is stripped from 802.1Q packets.
    /// See Table 63 for more details
    vlan_mode: bool,

    /// LAN Connected Device Reset (LCD_RST).  Controls a
    /// 0 – normal (operational)
    /// 1 – reset to PHY is asserted.
    /// The LCD_RST functionality is gated by the FWSM.RSPCIPHY bit.
    /// If the FWSM.RSPCIPHY bit is not set to ‘1’, then setting the LCD_RST has no impact.
    /// For proper operation Software or Firmware must also set the SWRST bit in the register at the same time.
    /// This bit is self-clearing
    lan_connected_device_reset: bool,
}

impl DeviceControls {
    /// Create a Device Controls struct from a u32
    pub fn from_u32(value: u32) -> DeviceControls {
        DeviceControls {
            duplex: if value & 1 == 1 {
                Duplex::Full
            } else {
                Duplex::Half
            },
            master_disable: ((value >> 2) & 1) == 1,
            speed: match (value >> 8) & 3 {
                0 => Speed::TenMb,
                1 => Speed::HundredMb,
                _ => Speed::OneGb,
            },
            force_speed: ((value >> 11) & 1) == 1,
            force_duplex: ((value >> 12) & 1) == 1,
            lanphypc_override: ((value >> 16) & 1) == 1,
            lanphypc_value: ((value >> 17) & 1) == 1,
            lcd_power_down: ((value >> 24) & 1) == 1,
            host_to_me: ((value >> 25) & 1) == 1,
            host_software_reset: ((value >> 26) & 1) == 1,
            receive_flow_control: ((value >> 27) & 1) == 1,
            transmit_flow_control: ((value >> 28) & 1) == 1,
            vlan_mode: ((value >> 30) & 1) == 1,
            lan_connected_device_reset: ((value >> 31) & 1) == 1,
        }
    }

    /// Generate a u32 from the Device Controls struct
    pub fn bits(&self) -> u32 {
        let speed = match self.speed {
            Speed::TenMb => 0,
            Speed::HundredMb => 1,
            Speed::OneGb => 2,
        };

        (self.duplex as u32)
            | ((self.master_disable as u8 as u32) << 2)
            | ((speed as u8 as u32) << 8)
            | ((self.force_speed as u8 as u32) << 11)
            | ((self.force_duplex as u8 as u32) << 12)
            | ((self.lanphypc_override as u8 as u32) << 16)
            | ((self.lanphypc_value as u8 as u32) << 17)
            | ((self.lcd_power_down as u8 as u32) << 24)
            | ((self.host_to_me as u8 as u32) << 25)
            | ((self.host_software_reset as u8 as u32) << 26)
            | ((self.receive_flow_control as u8 as u32) << 27)
            | ((self.transmit_flow_control as u8 as u32) << 28)
            | ((self.vlan_mode as u8 as u32) << 30)
            | ((self.lan_connected_device_reset as u8 as u32) << 31)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RxThresholdSize {
    Half = 0,
    Quarter = 1,
    Eighth = 2,
    Unknown = 0xff,
}

impl Default for RxThresholdSize {
    fn default() -> Self {
        RxThresholdSize::Half
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RxMulticastOffset {
    Offset47_38 = 0,
    Offset46_37 = 1,
    Offset45_36 = 2,
    Offset43_34 = 3,
}

impl Default for RxMulticastOffset {
    fn default() -> Self {
        RxMulticastOffset::Offset47_38
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RxBufferSize {
    Bytes2k,
    Bytes1k,
    Bytes512,
    Bytes256,
    Bytes16k,
    Bytes8k,
    Bytes4k,
}

impl Default for RxBufferSize {
    fn default() -> Self {
        RxBufferSize::Bytes8k
    }
}

/// Determine whether large or small buffers are enabled
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RxBufferSizeExtension {
    Small = 0,
    Large = 1,
}

impl Default for RxBufferSizeExtension {
    fn default() -> Self {
        RxBufferSizeExtension::Large
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RxDescriptorType {
    Legacy = 0,
    PacketSplit = 1,
}

impl Default for RxDescriptorType {
    fn default() -> Self {
        RxDescriptorType::Legacy
    }
}

/// Builder struct for Rx Controls register
///
/// Example:
///
/// print!("Creating controls\n");
/// let controls = RxControlsBuilder::default()
///                   .enable(true)
///                   .store_bad_packets(true)
///                   .unicast_promiscuous(true)
///                   .multicast_promiscuous(true)
///                   .receive_descriptor_minimum_threshold_size(RxThresholdSize::Half)
///                   .descriptor_type(RxDescriptorType::Legacy)
///                   .broadcast_accept_mode(true)
///                   .strip_ethernet_crc(true)
///                   .buffer_size(8192)
///                   .build();
///
/// print!("RX controls {:b}\n", controls.bits());
///
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct RxControlsBuilder {
    pub enable: bool,
    pub store_bad_packets: bool,
    pub unicast_promiscuous: bool,
    pub multicast_promiscuous: bool,
    pub long_packet: bool,
    pub receive_descriptor_minimum_threshold_size: RxThresholdSize,
    pub descriptor_type: RxDescriptorType,
    pub multicast_offset: RxMulticastOffset,
    pub broadcast_accept_mode: bool,
    pub buffer_size: RxBufferSize,
    pub pass_mac_control_frames: bool,
    pub buffer_size_extension: RxBufferSizeExtension,
    pub strip_ethernet_crc: bool,
    pub flexible_buffer_size: u16,
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct RxControls {
    enable: bool,
    store_bad_packets: bool,
    unicast_promiscuous: bool,
    multicast_promiscuous: bool,
    long_packet: bool,
    receive_descriptor_minimum_threshold_size: RxThresholdSize,
    descriptor_type: RxDescriptorType,
    multicast_offset: RxMulticastOffset,
    broadcast_accept_mode: bool,
    buffer_size: RxBufferSize,
    pass_mac_control_frames: bool,
    buffer_size_extension: RxBufferSizeExtension,
    strip_ethernet_crc: bool,
    flexible_buffer_size: u16,
}

impl RxControlsBuilder {
    pub fn new() -> RxControlsBuilder {
        RxControlsBuilder {
            enable: false,
            store_bad_packets: false,
            unicast_promiscuous: false,
            multicast_promiscuous: false,
            long_packet: false,
            receive_descriptor_minimum_threshold_size: RxThresholdSize::Half,
            descriptor_type: RxDescriptorType::Legacy,
            multicast_offset: RxMulticastOffset::Offset47_38,
            broadcast_accept_mode: false,
            buffer_size: RxBufferSize::Bytes8k,
            pass_mac_control_frames: false,
            buffer_size_extension: RxBufferSizeExtension::Large,
            strip_ethernet_crc: false,
            flexible_buffer_size: 0,
        }
    }

    pub fn enable(mut self, val: bool) -> RxControlsBuilder {
        self.enable = val;
        self
    }

    pub fn store_bad_packets(mut self, val: bool) -> RxControlsBuilder {
        self.store_bad_packets = val;
        self
    }

    pub fn unicast_promiscuous(mut self, val: bool) -> RxControlsBuilder {
        self.unicast_promiscuous = val;
        self
    }

    pub fn multicast_promiscuous(mut self, val: bool) -> RxControlsBuilder {
        self.multicast_promiscuous = val;
        self
    }

    pub fn long_packet(mut self, val: bool) -> RxControlsBuilder {
        self.long_packet = val;
        self
    }

    pub fn descriptor_type(mut self, val: RxDescriptorType) -> RxControlsBuilder {
        self.descriptor_type = val;
        self
    }

    pub fn receive_descriptor_minimum_threshold_size(
        mut self,
        val: RxThresholdSize,
    ) -> RxControlsBuilder {
        self.receive_descriptor_minimum_threshold_size = val;
        self
    }

    pub fn multicast_offset(mut self, val: RxMulticastOffset) -> RxControlsBuilder {
        self.multicast_offset = val;
        self
    }

    pub fn broadcast_accept_mode(mut self, val: bool) -> RxControlsBuilder {
        self.broadcast_accept_mode = val;
        self
    }

    pub fn strip_ethernet_crc(mut self, val: bool) -> RxControlsBuilder {
        self.strip_ethernet_crc = val;
        self
    }

    pub fn buffer_size(mut self, val: u16) -> RxControlsBuilder {
        match val {
            256 => {
                self.buffer_size = RxBufferSize::Bytes256;
                self.buffer_size_extension = RxBufferSizeExtension::Small;
            }
            516 => {
                self.buffer_size = RxBufferSize::Bytes512;
                self.buffer_size_extension = RxBufferSizeExtension::Small;
            }
            1024 => {
                self.buffer_size = RxBufferSize::Bytes1k;
                self.buffer_size_extension = RxBufferSizeExtension::Small;
            }
            2048 => {
                self.buffer_size = RxBufferSize::Bytes2k;
                self.buffer_size_extension = RxBufferSizeExtension::Small;
            }
            4096 => {
                self.buffer_size = RxBufferSize::Bytes4k;
                self.buffer_size_extension = RxBufferSizeExtension::Large;
            }
            8192 => {
                self.buffer_size = RxBufferSize::Bytes8k;
                self.buffer_size_extension = RxBufferSizeExtension::Large;
            }
            16384 => {
                self.buffer_size = RxBufferSize::Bytes16k;
                self.buffer_size_extension = RxBufferSizeExtension::Large;
            }
            _ => panic!("Invalid buffer_size given for receive packet"),
        }
        self
    }

    pub fn build(self) -> RxControls {
        RxControls {
            enable: self.enable,
            store_bad_packets: self.store_bad_packets,
            unicast_promiscuous: self.unicast_promiscuous,
            multicast_promiscuous: self.multicast_promiscuous,
            long_packet: self.long_packet,
            receive_descriptor_minimum_threshold_size:  /* self on new line */
                self.receive_descriptor_minimum_threshold_size,
            descriptor_type: self.descriptor_type,
            multicast_offset: self.multicast_offset,
            broadcast_accept_mode: self.broadcast_accept_mode,
            buffer_size: self.buffer_size,
            pass_mac_control_frames: self.pass_mac_control_frames,
            buffer_size_extension: self.buffer_size_extension,
            strip_ethernet_crc: self.strip_ethernet_crc,
            flexible_buffer_size: self.flexible_buffer_size,
        }
    }
}

impl RxControls {
    /// Generate u32 from the RxControls struct
    fn bits(&self) -> u32 {
        let (buffer_size, buffer_size_extension) = match self.buffer_size {
            RxBufferSize::Bytes2k => (0, 0),
            RxBufferSize::Bytes1k => (0, 1),
            RxBufferSize::Bytes512 => (0, 2),
            RxBufferSize::Bytes256 => (0, 3),
            RxBufferSize::Bytes16k => (1, 0),
            RxBufferSize::Bytes8k => (1, 1),
            RxBufferSize::Bytes4k => (1, 2),
        };

        ((self.enable as u8 as u32) << 1)
            | ((self.store_bad_packets as u8 as u32) << 2)
            | ((self.unicast_promiscuous as u8 as u32) << 3)
            | ((self.multicast_promiscuous as u8 as u32) << 4)
            | ((self.long_packet as u8 as u32) << 5)
            | ((self.receive_descriptor_minimum_threshold_size as u8 as u32) << 8)
            | ((self.descriptor_type as u8 as u32) << 10)
            | ((self.multicast_offset as u8 as u32) << 12)
            | ((self.broadcast_accept_mode as u8 as u32) << 15)
            | ((buffer_size as u8 as u32) << 16)
            | ((self.pass_mac_control_frames as u8 as u32) << 23)
            | ((buffer_size_extension as u8 as u32) << 25)
            | ((self.strip_ethernet_crc as u8 as u32) << 26)
            | ((self.flexible_buffer_size as u8 as u32) << 27)
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct TxControlsBuilder {
    enable: bool,
    pad_short_packets: bool,
    collision_threshold: u16,
    collision_distance: u32,
    retransmit_on_late_collisions: bool,
    read_request_threshold: u8,
}

/// Struct used for reading/modifying/setting the Transmit Controls register
///
/// print!("Disabling controls\n");
/// let controls = TxControlsBuilder::new()
///     .enable(false)
///     .pad_short_packets(true)
///     .build();
/// self.write_u32(TX_CONTROL, controls.bits());
///
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct TxControls {
    enable: bool,
    pad_short_packets: bool,

    /// Collision Threshold (CT).
    /// This determines the number of attempts at retransmission prior to giving up on the packet
    /// (not including the first transmission attempt).  While this can be varied, it should be set
    /// to a value of 15 in order to comply with the IEEE specification requiring a total of 16 attempts.
    /// The Ethernet back-off algorithm is implemented and clamps to the maximum number of slot-times after 10 retries.
    /// This field only has meaning when in half-duplex operation.
    collision_threshold: u16,

    /// Collision Distance (COLD).
    /// Specifies the minimum number of byte times which must elapse for proper CSMA/CD operation.
    /// Packets are padded with special symbols, not valid data bytes.
    /// Hardware checks and pads to this value plus one byte even in full-duplex operation.
    /// Default value is 64B – 512B times.
    collision_distance: u32,

    /// Re-transmit on Late Collision (RTLC).
    /// Enables the device to retransmit on a late collision event
    retransmit_on_late_collisions: bool,

    /// Read Request Threshold (RRTHRESH).
    /// These bits will define the threshold size for the intermediate buffer to determine when to send the
    /// read command to the Packet buffer. Threshold is defined as follow:
    /// RRTHRESH – 00b Threshold – 2 lines of 16 bytes
    /// RRTHRESH – 01b Threshold – 4 lines of 16 bytes
    /// RRTHRESH – 10b Threshold – 8 lines of 16 bytes
    /// RRTHRESH – 11b Threshold – No threshold (transfer data after all of the request is in the RFIFO)
    read_request_threshold: u8,
}

impl TxControls {
    fn bits(&self) -> u32 {
        (self.enable as u8 as u32) << 1
            | (self.pad_short_packets as u8 as u32) << 3
            | (self.collision_threshold as u32) << 4
            | (self.collision_distance as u32) << 12
            | (self.retransmit_on_late_collisions as u32) << 24
            | (1 << 28) // Forced reserved one bit
            | (self.read_request_threshold as u32) << 29
    }
}

impl TxControlsBuilder {
    pub fn new() -> TxControlsBuilder {
        TxControlsBuilder {
            enable: false,
            pad_short_packets: false,
            collision_threshold: 15,
            collision_distance: 63,
            retransmit_on_late_collisions: false,
            read_request_threshold: 1,
        }
    }

    pub fn enable(mut self, val: bool) -> TxControlsBuilder {
        self.enable = val;
        self
    }

    pub fn pad_short_packets(mut self, val: bool) -> TxControlsBuilder {
        self.pad_short_packets = val;
        self
    }

    pub fn build(self) -> TxControls {
        TxControls {
            enable: self.enable,
            pad_short_packets: self.pad_short_packets,
            collision_threshold: self.collision_threshold,
            collision_distance: self.collision_distance,
            retransmit_on_late_collisions: self.retransmit_on_late_collisions,
            read_request_threshold: self.read_request_threshold,
        }
    }
}

/* Constants used for the i219 Network Card */

/// Device Status
const DEVICE_CONTROL: u32 = 0x0;
/// Device Control
const DEVICE_STATUS: u32 = 0x8;

/// Interrupt Cause Read
const INTERRUPT_READ: u32 = 0xC0;
/// Interrupt Set Mask
const INTERRUPT_SET: u32 = 0xD0;
/// Interrupt Clear Mask
const INTERRUPT_CLEAR: u32 = 0xD8;

/// Receive Control
const RX_CONTROL: u32 = 0x100;
/// Receive Descriptor Base Address Low
const RX_DESCRIPTOR_LOW: u32 = 0x2800;
/// Receive Descriptor Base Address High
const RX_DESCRIPTOR_HIGH: u32 = 0x2804;
const RX_DESCRIPTOR_LENGTH: u32 = 0x2808;
const RX_DESCRIPTOR_HEAD: u32 = 0x2810;
const RX_DESCRIPTOR_TAIL: u32 = 0x2818;

/// Transmit Control
const TX_CONTROL: u32 = 0x400;
/// Transmit Descriptor Base Address Low
const TX_DESCRIPTOR_LOW: u32 = 0x3800;
/// Transmit Descriptor Base Address High
const TX_DESCRIPTOR_HIGH: u32 = 0x3804;
const TX_DESCRIPTOR_LENGTH: u32 = 0x3808;
const TX_DESCRIPTOR_HEAD: u32 = 0x3810;
const TX_DESCRIPTOR_TAIL: u32 = 0x3818;

const MULTICAST_TABLE_ARRAY: u32 = 0x5200;

/// Mac address
const RECEIVE_ADDRESS_LOW: u32 = 0x5400;

/// Statistic Registers
const CRC_ERROR_COUNT: u32 = 0x4000;
const RX_ERROR_COUNT: u32 = 0x400c;
const MISSED_PACKET_COUNT: u32 = 0x4010;
const RECEIVE_LENGTH_ERROR_COUNT: u32 = 0x4040;
const GOOD_PACKETS_RECEIVED: u32 = 0x4074;
const BROADCAST_PACKETS_RECEIVED: u32 = 0x4078;
const MULTICAST_PACKETS_RECEIVED: u32 = 0x407c;
const GOOD_PACKETS_TRANSMITTED: u32 = 0x4080;
const TOTAL_PACKETS_TRANSMITTED: u32 = 0x40d4;
const MULTICAST_PACKETS_TRANSMITTED: u32 = 0x40f0;
const BROADCAST_PACKETS_TRANSMITTED: u32 = 0x40f4;
const INTERRUPT_COUNT: u32 = 0x4100;
