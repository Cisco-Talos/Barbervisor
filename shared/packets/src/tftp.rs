use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

enum_with_unknown! {
    pub enum TftpOpcode(u16) {
        Read = 0x1,
        Write = 0x2,
        Data = 0x3,
        Ack = 0x4,
        Error = 0x5,
        OptionAck = 0x6,
    }
}

enum_with_unknown! {
    pub enum TransferType(&'static str) {
        Octet = "octet"
    }
}

impl fmt::Display for TftpOpcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &TftpOpcode::Read => write!(f, "Read"),
            &TftpOpcode::Write => write!(f, "Write"),
            &TftpOpcode::Data => write!(f, "Data"),
            &TftpOpcode::Ack => write!(f, "Ack"),
            &TftpOpcode::Error => write!(f, "Error"),
            &TftpOpcode::OptionAck => write!(f, "OptionAck"),
            &TftpOpcode::Unknown(id) => write!(f, "0x{:04x}", id),
        }
    }
}

/// A read/write wrapper around an Ethernet II frame buffer.
#[derive(Debug, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::field::*;

    // All Opcodes
    pub const OPCODE: Field = 0..2;

    // Ack/Data
    pub const BLOCK: Field = 2..4;

    // Data
    pub const DATA: Rest = 4..;

    // ReadReq
    pub const OPTIONS: Rest = 2..;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with TFTP structure
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the length of a buffer required to hold a packet with the payload
    /// of a given length.
    pub fn buffer_len(
        source_file: &str,
        transfer_type: &str,
        other_options: alloc::vec::Vec<(&str, &str)>,
    ) -> usize {
        let mut length = field::OPCODE.end + source_file.len() + 1 + transfer_type.len() + 1;
        for (left, right) in other_options.iter() {
            length += left.len() + 1;
            length += right.len() + 1;
        }
        length
    }

    /// Return the source file option field
    #[inline]
    pub fn source_file(&self) -> Option<&[u8]> {
        assert!(self.opcode() == TftpOpcode::Read || self.opcode() == TftpOpcode::Write);

        let data = self.buffer.as_ref();

        // Loop until we find a null byte and return the subsequent subslice
        for length in 0..data.len() {
            if data[field::OPTIONS.start + length] != 0 {
                continue;
            }

            let end = field::OPTIONS.start + length;
            return Some(&data[field::OPTIONS.start..end]);
        }

        return None;
    }

    /// Return the source file option field
    #[inline]
    pub fn transfer_type(&self) -> Option<&[u8]> {
        assert!(self.opcode() == TftpOpcode::Read || self.opcode() == TftpOpcode::Write);

        if self.source_file().is_none() {
            // print!("Invalid source file for Read Opcode\n");
            return None;
        }

        let data = self.buffer.as_ref();

        // start is the start of the transfer type option (+1 to skip over the null
        // byte from the source file
        let start =
            field::OPTIONS.start + self.source_file().expect("Failed to get source_file").len() + 1;

        // Loop until we find a null byte and return the subsequent subslice
        for length in 0..data[start..].len() {
            if data[start + length] != 0 {
                continue;
            }
            let end = start + length;
            return Some(&data[start..end]);
        }

        // Didn't find a null byte to end the transfer type
        return None;
    }

    /// Return the TftpOpcode field
    #[inline]
    pub fn opcode(&self) -> TftpOpcode {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::OPCODE]);
        TftpOpcode::from(raw)
    }

    /// Return the block field of an Ack or Data packet
    #[inline]
    pub fn block(&self) -> u16 {
        assert!(self.opcode() == TftpOpcode::Ack || self.opcode() == TftpOpcode::Data);
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::BLOCK])
    }

    /// Return the data field of a Data packet
    #[inline]
    pub fn data(&self) -> alloc::vec::Vec<u8> {
        assert!(self.opcode() == TftpOpcode::Data);
        let data = self.buffer.as_ref();
        data[field::DATA].to_vec()
    }

    /// Return the TftpOpcode field
    #[inline]
    pub fn other_options(&self) -> alloc::vec::Vec<(&str, &str)> {
        let data = self.buffer.as_ref();
        let mut options = alloc::vec::Vec::new();
        match self.opcode() {
            TftpOpcode::Read => {
                let start = field::OPTIONS.start
                    + self
                        .source_file()
                        .expect("Unable to find source file")
                        .len()
                    + 1 // Null terminator
                    + self
                        .transfer_type()
                        .expect("Unable to find transfer type")
                        .len()
                    + 1; // Null terminator

                let mut split = data[start..].split(|byte| byte == &0);

                // Push pairs of options into the options vec until we don't have any more
                loop {
                    match (split.next(), split.next()) {
                        (Some(left), Some(right)) => {
                            let left_str =
                                core::str::from_utf8(left).expect("Unable to utf8 left option");
                            let right_str =
                                core::str::from_utf8(right).expect("Unable to utf8 right option");
                            options.push((left_str, right_str));
                        }
                        _ => break,
                    }
                }

                options
            }

            _ => unimplemented!(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload, without checking for 802.1Q.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::OPTIONS]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the opcode field
    #[inline]
    pub fn set_opcode(&mut self, opcode: TftpOpcode) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::OPCODE], opcode.into());
    }

    /// Set the block field
    #[inline]
    pub fn set_block(&mut self, block: u16) {
        // Validate the opcode is being used is valid
        assert!(self.opcode() == TftpOpcode::Ack || self.opcode() == TftpOpcode::Data);

        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::BLOCK], block.into());
    }

    /// Set the block field
    #[inline]
    pub fn set_data(&mut self, new_data: &[u8]) {
        // Validate the opcode is being used is valid
        assert!(self.opcode() == TftpOpcode::Data);

        let data = self.buffer.as_mut();
        data[field::DATA].copy_from_slice(new_data);
    }

    /// Set the source file field
    #[inline]
    pub fn set_source_file(&mut self, file: &str) {
        // Validate the opcode is being used is valid
        assert!(self.opcode() == TftpOpcode::Read || self.opcode() == TftpOpcode::Write);

        // Insert the given source file
        let data = self.buffer.as_mut();
        let start = field::OPTIONS.start;
        let end = field::OPTIONS.start + file.len();
        data[start..end].copy_from_slice(file.as_bytes());
        data[end] = 0;
    }

    /// Set the transfer type field
    #[inline]
    pub fn set_transfer_type(&mut self, transfer_type: &str) {
        // Validate the opcode is being used is valid
        assert!(self.opcode() == TftpOpcode::Read || self.opcode() == TftpOpcode::Write);

        // Precalculate the current source_file to adjust properly
        let source_file_len = self.source_file().expect("Unable to get source_file").len() + 1;

        // Insert the given transfer type into the buffer
        let data = self.buffer.as_mut();
        let start = field::OPTIONS.start + source_file_len;
        let end = start + transfer_type.len();
        data[start..end].copy_from_slice(transfer_type.as_bytes());
        data[end] = 0;
    }

    /// Set the other options field
    #[inline]
    pub fn set_other_options(&mut self, other_options: alloc::vec::Vec<(&str, &str)>) {
        assert_eq!(self.opcode(), TftpOpcode::Read);

        // Precalculate the current source_file to adjust properly
        // +1 for null bytes
        let source_file_len = self
            .source_file()
            .expect("[set_other_options] Failed to get soure file")
            .len()
            + 1;
        let transfer_type_len = self
            .transfer_type()
            .expect("[set_other_options] Failed to get transfer type")
            .len()
            + 1;

        // Insert the given transfer type into the buffer
        let data = self.buffer.as_mut();
        let mut start = field::OPTIONS.start + source_file_len + transfer_type_len;
        // println!("{:?}", data);
        // println!("{:?}", data[start..]);

        for (left, right) in other_options.iter() {
            let left_len = left.len();
            let right_len = right.len();

            data[start..start + left_len].copy_from_slice(left.as_bytes());
            start += left_len;

            data[start] = 0;
            start += 1;

            data[start..start + right_len].copy_from_slice(right.as_bytes());
            start += right_len;

            data[start] = 0;
            start += 1;
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of a TFTP Read Request
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TftpReadRepr<'a> {
    pub opcode: TftpOpcode,
    pub source_file: &'a str,
    pub transfer_type: &'a str,
    pub other_options: alloc::vec::Vec<(&'a str, &'a str)>,
}

impl<'a> TftpReadRepr<'a> {
    /// Parse a TFTP Read request and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &'a Packet<&'a T>) -> TftpReadRepr<'a> {
        TftpReadRepr {
            opcode: frame.opcode(),
            source_file: core::str::from_utf8(
                frame
                    .source_file()
                    .expect("[TftpReadRepr::parse] failed to get source_file"),
            )
            .ok()
            .expect("[TftpReadRepr::parse] failed to get source_file after ok"),
            transfer_type: core::str::from_utf8(
                frame
                    .transfer_type()
                    .expect("[TftpReadRepr::parse] failed to get transfer_type"),
            )
            .ok()
            .expect("[TftpReadRepr::parse] failed to get source_file after ok"),
            other_options: frame.other_options(),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let mut length =
            field::OPCODE.end + self.source_file.len() + 1 + self.transfer_type.len() + 1;

        for (left, right) in self.other_options.iter() {
            length += left.len() + 1;
            length += right.len() + 1;
        }
        length
    }

    /// Emit a high-level representation into a TFTP Read request
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Packet<T>) {
        frame.set_opcode(TftpOpcode::Read);
        frame.set_source_file(self.source_file);
        frame.set_transfer_type(self.transfer_type);
        frame.set_other_options(self.other_options.clone());
    }
}

/// A high-level representation of a TFTP Write Request
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TftpWriteRepr<'a> {
    pub opcode: TftpOpcode,
    pub source_file: &'a str,
    pub transfer_type: &'a str,
}

impl<'a> TftpWriteRepr<'a> {
    /// Parse TFTP Write packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &'a Packet<&'a T>) -> TftpWriteRepr<'a> {
        TftpWriteRepr {
            opcode: frame.opcode(),
            source_file: core::str::from_utf8(
                frame
                    .source_file()
                    .expect("[TftpWriteRepr::parse] failed to get source_file"),
            )
            .ok()
            .expect("[TftpWriteRepr::parse] failed to get source_file"),
            transfer_type: core::str::from_utf8(
                frame
                    .transfer_type()
                    .expect("[TftpWriteRepr::parse] failed to get transfer_type"),
            )
            .ok()
            .expect("[TftpWriteRepr::parse] failed to get transfer_type"),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let length = field::OPCODE.end + self.source_file.len() + 1 + self.transfer_type.len() + 1;
        length
    }

    /// Emit a high-level representation into an TFTP Write packet
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Packet<T>) {
        frame.set_opcode(TftpOpcode::Write);
        frame.set_source_file(self.source_file);
        frame.set_transfer_type(self.transfer_type);
    }
}

/// A high-level representation of a TFTP Ack Request
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TftpAckRepr {
    pub opcode: TftpOpcode,
    pub block: u16,
}

impl TftpAckRepr {
    /// Parse a TFTP Ack and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &Packet<&T>) -> TftpAckRepr {
        TftpAckRepr {
            opcode: frame.opcode(),
            block: frame.block(),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let length = field::OPCODE.end + field::BLOCK.end;
        length
    }

    /// Emit a high-level representation into a TFTP Ack
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Packet<T>) {
        frame.set_opcode(TftpOpcode::Ack);
        frame.set_block(self.block);
    }
}

/// A high-level representation of a TFTP Ack Request
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TftpOptionAckRepr {
    pub opcode: TftpOpcode,
}

impl TftpOptionAckRepr {
    /// Parse a TFTP Ack and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &Packet<&T>) -> TftpOptionAckRepr {
        TftpOptionAckRepr {
            opcode: frame.opcode(),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let length = field::OPCODE.end + field::BLOCK.end;
        length
    }

    /// Emit a high-level representation into a TFTP Ack
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Packet<T>) {
        frame.set_opcode(TftpOpcode::OptionAck);
    }
}

/// A high-level representation of a TFTP Data packet
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TftpDataRepr {
    pub opcode: TftpOpcode,
    pub block: u16,
    pub data: alloc::vec::Vec<u8>,
}

impl TftpDataRepr {
    /// Parse an TFTP Data packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &Packet<&T>) -> TftpDataRepr {
        TftpDataRepr {
            opcode: frame.opcode(),
            block: frame.block(),
            data: frame.data(),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let length = 2 + 2 + self.data.len();
        length
    }

    /// Emit a high-level representation into a TFTP Data packet
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Packet<T>) {
        frame.set_opcode(TftpOpcode::Data);
        frame.set_block(self.block);
        frame.set_data(&self.data);
    }
}

#[cfg(test)]
mod test_tftp {
    // Tests that are valid only with "proto-ipv4"
    use super::*;

    static tftp_read_packet: [u8; 33] = [
        0x00, 0x01, 0x62, 0x61, 0x72, 0x62, 0x65, 0x72, 0x73, 0x6c, 0x69, 0x63, 0x65, 0x2e, 0x6b,
        0x65, 0x72, 0x6e, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00, 0x74, 0x73, 0x69, 0x7a, 0x65,
        0x00, 0x30, 0x00,
    ];

    #[test]
    fn tftp_read_test() {
        /*
        0000   00 01 62 61 72 62 65 72 73 6c 69 63 65 2e 6b 65   ..barberslice.ke
        0010   72 6e 00 6f 63 74 65 74 00 74 73 69 7a 65 00 30   rn.octet.tsize.0
        0020   00                                                .
        */

        let mut frame = Packet::new_unchecked(&tftp_read_packet[..]);

        assert_eq!(frame.opcode(), TftpOpcode::Read);
        assert_eq!(frame.source_file(), Some("barberslice.kern".as_bytes()));
        assert_eq!(frame.transfer_type(), Some("octet".as_bytes()));
        assert_eq!(frame.other_options(), vec![("tsize", "0")]);
    }

    #[test]
    fn tftp_read_construct() {
        let read_req = TftpReadRepr {
            opcode: TftpOpcode::Read,
            source_file: "barberslice.kern",
            transfer_type: "octet",
            other_options: [("tsize", "0")].to_vec(),
        };

        let packet_length = read_req.buffer_len();
        let mut bytes = vec![0xee; packet_length];
        let mut frame = Packet::new_unchecked(&mut bytes);

        read_req.emit(&mut frame);
        assert_eq!(&frame.into_inner()[..], &tftp_read_packet[..]);
    }
}
