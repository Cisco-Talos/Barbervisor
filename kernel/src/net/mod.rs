use crate::pci::BarType;
use cpuio::Port;

use packets::ethernet::{
    Address as MacAddress, Frame as EthernetFrame, Protocol as EthernetProtocol,
    Repr as EthernetRepr,
};
use packets::ip::Protocol as IpProtocol;
use packets::ipv4::{Address as Ipv4Address, Packet as Ipv4Packet, Repr as Ipv4Repr};
use packets::phy::ChecksumCapabilities;
use packets::tftp::{
    Packet as TftpPacket, TftpAckRepr, TftpDataRepr, TftpOpcode, TftpReadRepr, 
    TftpWriteRepr,
};
use packets::udp::{Packet as UdpPacket, Repr as UdpRepr};

use spin::Mutex;
use crate::i219::I219;

pub mod i219;

pub static mut LAPTOP_IP_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 231]);
pub static mut DESKTOP_IP_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 230]);
pub static mut LAPTOP_MAC_ADDR: MacAddress = MacAddress([0xa0, 0x36, 0x9f, 
                                                         0x21, 0x4a, 0x87]);
pub static mut DESKTOP_MAC_ADDR: MacAddress = MacAddress([0xb4, 0x96, 0x91, 
                                                          0xec, 0xdf, 0xb6]);

lazy_static! {
    static ref DRIVER: Mutex<I219> = {
        match crate::pci::find_device(0x8086, 0x15b7) {
            Some(eth) => {
                print!("Found NIC for Lenovo laptop!\n");
                Mutex::new(I219::new(eth))
            }
            None => panic!("Unable to find the ethernet card for I219")
        }
    };
}

const BOCHS: bool = false;

pub fn get_file(filename: &str) -> alloc::vec::Vec<u8> {
    if BOCHS {
        print!("Getfile: {}\n", filename);
        if filename == "SNAPSHOT_regs" {
            print!("GET_FILE: USING BOCH\n");
            let data = include_bytes!("..\\..\\..\\tftp-server\\SNAPSHOT_regs");
            return data.to_vec();
        }
        return alloc::vec::Vec::new();
    }

    let res = {
        // let mut driver = DRIVER.lock();
        let mut driver = loop {
            match DRIVER.try_lock() {
                Some(d) => break d,
                None => {
                    // print!("gf ");
                }
            }
        };

        driver.get_file(filename)
        // implicit drop of the lock
    };

    res
}

pub fn put_file(filename: &str, contents: &[u8]) {
    // let timer_start_put_file = time::rdtsc();
    if BOCHS {
            print!("PUT_FILE: USING BOCH\n");
        return;
    }

    {
        // let mut driver = DRIVER.lock();
        let mut driver = loop {
            match DRIVER.try_lock() {
                Some(d) => break d,
                None => {
                    // print!("pf ");
                }
            }
        };
        let _ = driver.put_file(filename, contents);
    }
}

pub const TFTP_PORT: u16 = 9898;

/// Trait for each Network Driver
pub trait NetworkDriver {
    /// Bar type for this device
    fn bar_type(&self) -> BarType;

    /// Either MMIO or IO base address
    fn mem_base(&self) -> u64 {
        unimplemented!();
    }

    /// Either MMIO or IO base address
    fn io_base(&self) -> u16 {
        unimplemented!();
    }

    #[allow(unused_variables)]
    /// Network device implementation of how to send a packet for the device
    fn send_packet(&self, payload: &[u8]) {
        unimplemented!();
    }

    /// Network device implementation of receiving a packet from the device
    fn next_packet(&self) -> EthernetFrame<&[u8]> {
        unimplemented!();
    }

    /// Function called to reset the NIC prior to soft reboot
    fn reset(&mut self) {
        unimplemented!();
    }

    /// Function called to clear the buffers to the NIC
    fn clear(&mut self) {
        unimplemented!();
    }

    fn read_u8(&self, reg: u16) -> u8 {
        match self.bar_type() {
            BarType::MemSpace32 => unsafe { *((self.mem_base() + reg as u64) as *const u8) },
            BarType::MemSpace64 => unsafe { *((self.mem_base() + reg as u64) as *const u8) },
            BarType::IoSpace => {
                let mut config_address_port: Port<u16> = unsafe { Port::new(self.io_base()) };
                config_address_port.write(reg.into());

                let mut config_data_port: Port<u8> = unsafe { Port::new(self.io_base() + 4) };
                config_data_port.read()
            }
            BarType::Unused => panic!("Attemped to read_u8 from Unused BAR"),
        }
    }

    fn read_u16(&self, reg: u16) -> u16 {
        match self.bar_type() {
            BarType::MemSpace32 => unsafe { *((self.mem_base() + reg as u64) as *const u16) },
            BarType::MemSpace64 => unsafe { *((self.mem_base() + reg as u64) as *const u16) },
            BarType::IoSpace => {
                let mut config_address_port: Port<u16> = unsafe { Port::new(self.io_base()) };
                config_address_port.write(reg.into());

                let mut config_data_port: Port<u16> = unsafe { Port::new(self.io_base() + 4) };
                config_data_port.read()
            }
            BarType::Unused => panic!("Attemped to read_u16 from Unused BAR"),
        }
    }

    fn read_u32(&self, reg: u32) -> u32 {
        match self.bar_type() {
            BarType::MemSpace32 => unsafe { *((self.mem_base() + reg as u64) as *const u32) },
            BarType::MemSpace64 => unsafe { *((self.mem_base() + reg as u64) as *const u32) },
            BarType::IoSpace => {
                panic!("IoSpace not impl");
                /*
                let mut config_address_port: Port<u16> = unsafe { Port::new(self.io_base()) };
                config_address_port.write(reg.into());

                let mut config_data_port: Port<u32> = unsafe { Port::new(self.io_base() + 4) };
                config_data_port.read()
                */
            }
            BarType::Unused => panic!("Attemped to read_u32 from Unused BAR"),
        }
    }

    fn read_u64(&self, reg: u16) -> u64 {
        match self.bar_type() {
            BarType::MemSpace32 => unsafe { *((self.mem_base() + reg as u64) as *const u64) },
            BarType::MemSpace64 => unsafe { *((self.mem_base() + reg as u64) as *const u64) },
            BarType::IoSpace => {
                panic!("Tried to read_u64 from IoSpace.. Not currently implemented");
            }
            BarType::Unused => panic!("Attemped to read_u64 from Unused BAR"),
        }
    }

    fn write_u8(&self, reg: u16, value: u8) {
        match self.bar_type() {
            BarType::MemSpace32 => unsafe { *((self.mem_base() + reg as u64) as *mut u8) = value },
            BarType::MemSpace64 => unsafe { *((self.mem_base() + reg as u64) as *mut u8) = value },
            BarType::IoSpace => {
                let mut config_address_port: Port<u16> = unsafe { Port::new(self.io_base()) };
                config_address_port.write(reg.into());

                let mut config_data_port: Port<u8> = unsafe { Port::new(self.io_base() + 4) };
                config_data_port.write(value);
            }
            BarType::Unused => panic!("Attemped to write_u8 from Unused BAR"),
        }
    }

    fn write_u16(&self, reg: u16, value: u16) {
        match self.bar_type() {
            BarType::MemSpace32 => unsafe { *((self.mem_base() + reg as u64) as *mut u16) = value },
            BarType::MemSpace64 => unsafe { *((self.mem_base() + reg as u64) as *mut u16) = value },
            BarType::IoSpace => {
                let mut config_address_port: Port<u16> = unsafe { Port::new(self.io_base()) };
                config_address_port.write(reg.into());

                let mut config_data_port: Port<u16> = unsafe { Port::new(self.io_base() + 4) };
                config_data_port.write(value);
            }
            BarType::Unused => panic!("Attemped to write_u16 from Unused BAR"),
        }
    }

    fn write_u32(&self, reg: u32, value: u32) {
        match self.bar_type() {
            BarType::MemSpace32 => unsafe { *((self.mem_base() + reg as u64) as *mut u32) = value },
            BarType::MemSpace64 => unsafe { *((self.mem_base() + reg as u64) as *mut u32) = value },
            BarType::IoSpace => {
                panic!("write_u32 in IoSpace");
                /*
                let mut config_address_port: Port<u16> = unsafe { Port::new(self.io_base()) };
                config_address_port.write(reg.into());

                let mut config_data_port: Port<u32> = unsafe { Port::new(self.io_base() + 4) };
                config_data_port.write(value);
                */
            }
            BarType::Unused => panic!("Attemped to write_u32 from Unused BAR"),
        }
    }

    fn write_u64(&self, reg: u16, value: u64) {
        match self.bar_type() {
            BarType::MemSpace32 => unsafe { *((self.mem_base() + reg as u64) as *mut u64) = value },
            BarType::MemSpace64 => unsafe { *((self.mem_base() + reg as u64) as *mut u64) = value },
            BarType::IoSpace => {
                panic!("Tried to write_u64 from IoSpace.. Not currently implemented");
            }
            BarType::Unused => panic!("Attemped to write_u64 from Unused BAR"),
        }
    }

    /// Encapsulate and send a given TFTP packet with a Ethernet/IP/UDP header
    fn send_tftp_packet(&self, tftp_packet: &[u8], dst_port: u16) {
        // Construct UDP payload containing TFTP
        let udp_packet_repr = UdpRepr {
            src_port: 31337,
            dst_port: dst_port,
            payload: tftp_packet,
        };

        let mut udp_bytes = vec![0xee; udp_packet_repr.buffer_len()];
        let mut udp_packet = UdpPacket::new_unchecked(&mut udp_bytes);

        unsafe {
            udp_packet_repr.emit(
                &mut udp_packet,
                &LAPTOP_IP_ADDR.into(),
                &DESKTOP_IP_ADDR.into(),
                &ChecksumCapabilities::default(),
            );
        }

        // Construct IPv4 Packet
        let ipv4_packet_repr = unsafe {
            Ipv4Repr {
                src_addr: LAPTOP_IP_ADDR,
                dst_addr: DESKTOP_IP_ADDR,
                protocol: IpProtocol::Udp,
                payload_len: udp_bytes.len(),
                hop_limit: 64,
            }
        };


        let mut ipv4_bytes = vec![0xee; ipv4_packet_repr.buffer_len()];
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut ipv4_bytes);
        let _repr = ipv4_packet_repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());

        let ether_packet_repr = unsafe {
            // Construct Ethernet Packet
            EthernetRepr {
                src_addr: LAPTOP_MAC_ADDR,
                dst_addr: DESKTOP_MAC_ADDR,
                protocol: EthernetProtocol::Ipv4,
            }
        };

        let mut ether_bytes = vec![0xee; ether_packet_repr.buffer_len()];
        let mut ether_frame = EthernetFrame::new_unchecked(&mut ether_bytes);
        let _repr = ether_packet_repr.emit(&mut ether_frame);

        // Concat bytes to form final packet
        let mut packet = vec![];
        packet.extend_from_slice(&ether_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&udp_bytes);

        // Send final constructed packet
        self.send_packet(&packet);
    }

    /// Send a TFTP Read Request for the given filename
    fn tftp_read_request(&mut self, filename: &str) {
        let read_req = TftpReadRepr {
            opcode: TftpOpcode::Read,
            source_file: filename,
            transfer_type: "octet",
            other_options: [("blksize", "1428")].to_vec(),
        };

        let packet_length = read_req.buffer_len();
        let mut bytes = vec![0xee; packet_length];
        let mut frame = TftpPacket::new_unchecked(&mut bytes);

        read_req.emit(&mut frame);

        // The initial TFTP request goes to port TFTP_PORT
        self.send_tftp_packet(&bytes, TFTP_PORT);
    }

    /// Send a TFTP Write Request for the given filename
    fn tftp_write_request(&mut self, filename: &str) {
        let write_req = TftpWriteRepr {
            opcode: TftpOpcode::Write,
            source_file: filename,
            transfer_type: "octet",
        };

        let packet_length = write_req.buffer_len();

        let mut bytes = vec![0x0; packet_length];
        let mut frame = TftpPacket::new_unchecked(&mut bytes);

        write_req.emit(&mut frame);

        // The initial TFTP request goes to port TFTP_PORT
        self.send_tftp_packet(&bytes, TFTP_PORT);
    }

    /// Send a TFTP Data packet to the given destination port for the given block
    /// With the given data
    fn tftp_data(&mut self, dst_port: u16, block: u16, data: &[u8]) {
        let tftp_data_repr = TftpDataRepr {
            opcode: TftpOpcode::Data,
            block,
            data: data.to_vec(),
        };

        let packet_length = tftp_data_repr.buffer_len();
        let mut bytes = vec![0x0; packet_length];
        let mut frame = TftpPacket::new_unchecked(&mut bytes);

        tftp_data_repr.emit(&mut frame);

        // Each subsequent TFTP packet is sent to the destination port of the received packet
        self.send_tftp_packet(&bytes, dst_port);
    }

    /// Send a TFTP Acknowledgement packet to the given destination port for the given block
    fn tftp_ack(&mut self, dst_port: u16, block: u16) {
        let tftp_ack_repr = TftpAckRepr {
            opcode: TftpOpcode::Ack,
            block,
        };

        let packet_length = tftp_ack_repr.buffer_len();
        let mut bytes = vec![0x0; packet_length];
        let mut frame = TftpPacket::new_unchecked(&mut bytes);

        tftp_ack_repr.emit(&mut frame);

        // Each subsequent TFTP packet is sent to the destination port of the received packet
        self.send_tftp_packet(&bytes, dst_port);
    }

    /// Return the next received tftp packet
    fn next_udp_packet(&self) -> UdpPacket<&[u8]> {
        for _ in 0..10 {
            let ethernet = self.next_packet();
            let ipv4_bytes = ethernet.payload();
            let ipv4 = Ipv4Packet::new_unchecked(ipv4_bytes);
            if ipv4.protocol() != IpProtocol::Udp {
                print!("Received non-udp packet?! {:?}\n", ipv4.protocol());
                continue;
            }

            let udp_bytes = ipv4.payload();
            let udp = UdpPacket::new_unchecked(udp_bytes);
            let dst_port = udp.dst_port();
            if dst_port == 31337 {
                return udp;
            }
        }

        panic!("next_udp_packet timeout");
    }

    /// Get the given file via TFTP
    fn get_file(&mut self, filename: &str) -> alloc::vec::Vec<u8> {
        // Send initial read request
        self.tftp_read_request(filename);

        let mut file_contents = vec![];
        loop {
            let packet = self.next_udp_packet();
            let src_port = packet.src_port();
            let tftp_bytes = TftpPacket::new_unchecked(packet.payload());
            match tftp_bytes.opcode() {
                TftpOpcode::OptionAck => {
                    // Block is always zero for OptionAck
                    self.tftp_ack(src_port, 0);
                }
                TftpOpcode::Data => {
                    let curr_block = tftp_bytes.block();
                    let new_data = tftp_bytes.data();
                    file_contents.extend_from_slice(&new_data);

                    self.tftp_ack(src_port, curr_block);

                    // If the data is less than max, it is the last packet
                    if new_data.len() < 1428 {
                        break;
                    }
                }
                _ => {
                    print!("Opcode Received {:?}\n", tftp_bytes.opcode());
                    unimplemented!();
                }
            }
        }

        file_contents
    }

    /// Put the given contents as the given filename via TFTP
    fn put_file(&mut self, filename: &str, contents: &[u8]) {
        // print!("Putting file: {}\n", filename);

        // Send initial write request
        self.tftp_write_request(filename);

        let mut chunks = contents.chunks(512);

        let mut curr_block = 0;
        loop {
            let packet = self.next_udp_packet();
            let src_port = packet.src_port();
            let tftp_bytes = TftpPacket::new_unchecked(packet.payload());

            match tftp_bytes.opcode() {
                TftpOpcode::Ack => {
                    if let Some(curr_chunk) = chunks.next() {
                        // Still have data left to send
                        assert!(tftp_bytes.block() == curr_block as u16);
                        curr_block += 1;
                        self.tftp_data(src_port, curr_block as u16, curr_chunk);
                    } else {
                        curr_block += 1;
                        self.tftp_data(src_port, curr_block as u16, &[]);
                        return;
                    }
                }
                _ => unimplemented!(),
            }
        }
    }
}
