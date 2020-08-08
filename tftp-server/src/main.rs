extern crate packets;

use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use std::net;

use packets::tftp::{
    Packet as TftpPacket, TftpAckRepr, TftpDataRepr, TftpOpcode, TftpOptionAckRepr
};

/// Returns the virtual addresses and the virt to phys tranlations mapping from
/// the data of a vbox core file
pub fn translate_phys<R: Read + Seek>(vaddr: u64, cr3: u64, phys_data: &mut R) -> usize {
    let mut curr_page = cr3;

    // Calculate the components for each level of the page table from the vaddr.
    let cr_offsets: [u64; 4] = [
        ((vaddr >> 39) & 0x1ff), /* 512 GiB */
        ((vaddr >> 30) & 0x1ff), /*   1 GiB */
        ((vaddr >> 21) & 0x1ff), /*   2 MiB */
        ((vaddr >> 12) & 0x1ff), /*   4 KiB */
    ];

    // For each level in the page table
    for (_depth, curr_offset) in cr_offsets.iter().enumerate() {
        /* Get the page table entry */
        let start_offset = (curr_page + (curr_offset * 8)) as usize;
        let mut buffer = [0u8; 8];
        phys_data.seek(SeekFrom::Start(start_offset as u64))
            .expect("Unable to seek in phys_data");
        phys_data.read_exact(&mut buffer).expect("Unable to read_exact for phys_data");
        let entry = u64::from_le_bytes(buffer);

        // Get the physical address of the next level
        if entry & 1 << 7 > 0 {
            curr_page = (entry & 0xffff_ffe0_0000) | (vaddr & 0x1f_ffff);
            return curr_page as usize;
        }

        //  Get the physical address of the next level 
        curr_page = entry & 0xffff_ffff_f000;
        if curr_page == 0 {
            return 0;
        }
    }

    curr_page as usize
}

const BLOCK_SIZE: usize = 1428;

enum DataState {
    Read,
    Write,
}

/// Main TFTP parsing loop for the given UdpSocket
fn read_message(socket: &net::UdpSocket) {
    let mut buf: [u8; 1600];
    let mut filedata = Vec::new();
    let mut writefile: Option<File> = None;
    let mut state = None;
    let mut curr_block = 0;
    let mut phys_data =
        File::open("../snapshot/snapshot.phys").expect("\nFILE NOT FOUND: snapshot.phys\n");
    let mut _total_pages = 0;

    loop {
        // Clear the current receive buffer
        buf = [0; 1600];

        // Wait for an packet
        let result = socket.recv_from(&mut buf);
        match result {
            Ok((count, src)) => {
                let packet = TftpPacket::new_unchecked(&mut buf[..count]);
                match packet.opcode() {
                    TftpOpcode::Read => {
                        // Get the filename requested to be read
                        let filename = match std::str::from_utf8(
                            &packet.source_file().expect("Unable to get source_file"),
                        ) {
                            Ok(name) => name,
                            Err(msg) => panic!( "Unable to get str for source_file: {}", msg),
                        };

                        println!("File: {}", filename);
                        state = Some(DataState::Read);

                        /* Read current file to filedata */
                        let mut full_path = String::from("./");
                        full_path.push_str(filename);
                        filedata = Vec::new();
                        match File::open(&full_path) {
                            Ok(mut file) => {
                                let _ = file.read_to_end(&mut filedata).expect("Error reading");
                            }
                            Err(msg) => {
                                // Start the custom features for our TFTP Server
                                
                                if filename.contains("_page_") {
                                    /* expecting file like SNAPSHOT_page_00000000dead0000
                                     * asking for physical page at 0xdead0000 */
                                    let phys_addr = usize::from_str_radix(
                                        filename.split("_").last().unwrap(),
                                        16,
                                    )
                                    .expect("unable to convert to u64");

                                    let mut buffer = [0u8; 0x1000];
                                    phys_data.seek(SeekFrom::Start(phys_addr as u64))
                                        .expect("Unable to seek in phys_data");
                                    phys_data.read_exact(&mut buffer)
                                        .expect("Unable to read_exact in phys_data");
                                    filedata = buffer.to_vec();

                                    // HalRequestSoftwareInterrupt
                                    const HALREQUESTSOFTWAREINTERRUPT: [u8; 40] = [
                                        0x48, 0x83, 0xec, 0x48, 0x33, 0xc0, 0xf, 0x57, 0xc0, 0x80,
                                        0xf9, 0x1, 0x48, 0x89, 0x44, 0x24, 0x30, 0xf, 0x11, 0x44,
                                        0x24, 0x20, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0xc7, 0x44, 0x24,
                                        0x20, 0x5, 0x0, 0x0, 0x0, 0x8d, 0x50, 0x1f, 0x8d, 0x42,
                                    ];

                                    if filedata.len() > HALREQUESTSOFTWAREINTERRUPT.len() {
                                        for i in 0..(filedata.len() - HALREQUESTSOFTWAREINTERRUPT.len()) {
                                            if &filedata[i..i + 20] == &HALREQUESTSOFTWAREINTERRUPT[..20] 
                                                && &filedata[i + 20..i + 40] == &HALREQUESTSOFTWAREINTERRUPT[20..] {
                                                print!("Found HalRequestSoftware breakpoint!\n");
                                                print!("Before: {:?}\n", &filedata[i..i + 5]);
                                                // filedata[i+0] = 0xcc;
                                                /* mov eax, 0xdeaddead; vmcall  */
                                                /*
                                                filedata[i+0] = 0xb8;
                                                filedata[i+1] = 0xad;
                                                filedata[i+2] = 0xde;
                                                filedata[i+3] = 0xad;
                                                filedata[i+4] = 0xde;
                                                filedata[i+5] = 0x0f;
                                                filedata[i+6] = 0x01;
                                                filedata[i+7] = 0xc1;
                                                */
                                                print!("After : {:?}\n", &filedata[i..i + 5]);
                                            }
                                        }
                                    }

                                    // HalProcessorIdle
                                    const HALPROCESSORIDLE: [u8; 16] = [
                                        0x48, 0x83, 0xec, 0x28, 0xe8, 0xe7, 0x32, 0xfa, 0xff, 0x48, 0x83,
                                        0xc4, 0x28, 0xfb, 0xf4, 0xc3,
                                    ];
                                    if filedata.len() > HALPROCESSORIDLE.len() {
                                        for i in 0..(filedata.len() - HALPROCESSORIDLE.len()) {
                                            if &filedata[i..i + HALPROCESSORIDLE.len()] == &HALPROCESSORIDLE {
                                                print!("Found HalProcessorIdle breakpoint!\n");
                                                print!("Before: {:?}\n", &filedata[i..i + 5]);
                                                filedata[i+0] = 0xcc;
                                                // filedata[i+0] = 0x0f;
                                                // filedata[i+1] = 0x01;
                                                // filedata[i+2] = 0xc1;
                                                print!("After : {:?}\n", &filedata[i..i + 5]);
                                            }
                                        }
                                    }
                                } else if filename.contains("_translate_") {
                                    /* expecting filename like
                                     * SNAPSHOT_translate_00000000cafe0000_00000000deadb000
                                     * asking to translate vaddr 0xdeadb000 using cr3 0xcafe0000 */

                                    println!("Translate File: {}", filename);
                                    let mut split = filename.split("_");
                                    let _snapshot = split.next().unwrap();
                                    let _translate = split.next().unwrap();
                                    let cr3 = split.next().unwrap();
                                    let vaddr = split.next().unwrap();

                                    // Get the cr3 and guest virt
                                    let cr3 =
                                        u64::from_str_radix(cr3, 16).unwrap() & 0xffff_ffff_f000;
                                    let vaddr = u64::from_str_radix(vaddr, 16).unwrap();

                                    // Translate the guest virt address to guest phys address
                                    let phys_addr = translate_phys(vaddr, cr3, &mut phys_data);

                                    // Send the translated address back
                                    filedata = phys_addr.to_le_bytes().to_vec();
                                } 
                                else {
                                    print!("Can't open file {}: {}", &full_path, msg);
                                    filedata = Vec::new();
                                }
                            }
                        };

                        // Create a OptionAck
                        let tftp_option_ack_repr = TftpOptionAckRepr {
                            opcode: TftpOpcode::OptionAck,
                        };

                        // Create a packet for the OptionAck
                        let packet_length = tftp_option_ack_repr.buffer_len();
                        let mut bytes = vec![0x0; packet_length];
                        let mut frame = TftpPacket::new_unchecked(&mut bytes);

                        // Emit the bytes for the OptionAck
                        tftp_option_ack_repr.emit(&mut frame);

                        // Send the OptionAck
                        socket.send_to(&bytes, &src).expect("send_to failed");
                    }
                    TftpOpcode::Ack => {
                        match state {
                            /* Responding to Read state */
                            Some(DataState::Read) => {
                                let curr_block: usize = packet.block() as usize;
                                let upper_bound =
                                    std::cmp::min((curr_block + 1) * BLOCK_SIZE, filedata.len());
                                let data = &filedata[curr_block * BLOCK_SIZE..upper_bound];

                                // Create a Data packet
                                let tftp_data_repr = TftpDataRepr {
                                    opcode: TftpOpcode::Data,
                                    block: (curr_block + 1) as u16,
                                    data: data.to_vec(),
                                };

                                // Create a packet for the Data
                                let packet_length = tftp_data_repr.buffer_len();
                                let mut bytes = vec![0x0; packet_length];
                                let mut frame = TftpPacket::new_unchecked(&mut bytes);

                                // Emit the bytes for the Data
                                tftp_data_repr.emit(&mut frame);

                                // Send the Data bytes
                                socket.send_to(&bytes, &src).expect("send_to failed");

                                // Finished sending this file.. reset the filedata
                                if upper_bound == filedata.len() {
                                    state = None;
                                    filedata = Vec::new();
                                }
                            }
                            _ => {
                                continue;
                            }
                        }
                    }
                    TftpOpcode::Write => {
                        let filename = {
                            let filename: String = match std::str::from_utf8(
                                &packet.source_file().expect("Unable to get source_file"),
                            ) {
                                Ok(name) => {
                                    // If we see a filename known to be sent by the kernel, save
                                    // those files in a local project directory
                                    if name.contains(".coverage") {
                                        format!("./project/coverages/{}", name)
                                    } else if name.contains("corpus-") {
                                        format!("./project/inputs/{}", name)
                                    } else {
                                        name.to_string()
                                    }
                                }
                                Err(msg) => panic!( "Unable to get str for source_file: {}", msg),
                            };

                            println!("Write File: {}", filename);
                            filename
                        };

                        state = Some(DataState::Write);
                        writefile =
                            Some(File::create(filename).expect("Unable to create write filename"));
                        filedata = Vec::new();
                        curr_block = 0;

                        // Create an Ack
                        let tftp_ack_repr = TftpAckRepr {
                            opcode: TftpOpcode::Ack,
                            block: curr_block,
                        };

                        curr_block += 1;

                        // Create a packet for the Ack
                        let packet_length = tftp_ack_repr.buffer_len();
                        let mut bytes = vec![0x0; packet_length];
                        let mut frame = TftpPacket::new_unchecked(&mut bytes);

                        // Emit the bytes for the Ack
                        tftp_ack_repr.emit(&mut frame);

                        // Send the Ack packet
                        socket.send_to(&bytes, &src).expect("send_to failed");
                    }
                    TftpOpcode::Data => {
                        match state {
                            // Responding to Write state
                            Some(DataState::Write) => {
                                let mut packet_data = packet.data();
                                let data_len = packet_data.len();

                                // Done receiving the file
                                if data_len == 0 {
                                    match writefile {
                                        None => panic!("Write data with no writefile written"),
                                        Some(mut file) => {
                                            file.write_all(&filedata)
                                                .expect("Unable to write all");
                                        }
                                    }

                                    state = None;
                                    filedata = Vec::new();
                                    writefile = None;
                                    curr_block = 0;
                                    continue;
                                }

                                filedata.append(&mut packet_data);

                                // Create an Ack packet
                                let tftp_ack_repr = TftpAckRepr {
                                    opcode: TftpOpcode::Ack,
                                    block: curr_block,
                                };

                                // Create a packet for the Ack
                                let packet_length = tftp_ack_repr.buffer_len();
                                let mut bytes = vec![0x0; packet_length];
                                let mut frame = TftpPacket::new_unchecked(&mut bytes);

                                // Emit the bytes for the Ack
                                tftp_ack_repr.emit(&mut frame);

                                // Send the Ack bytes
                                socket.send_to(&bytes, &src).expect("send_to failed");

                                curr_block += 1;
                            }
                            _ => panic!("Data without a state"),
                        }
                    }
                    _ => unimplemented!(),
                }
            }
            _ => unimplemented!(),
        }
    }
}

fn socket(listen_on: net::SocketAddr) -> net::UdpSocket {
    let attempt = net::UdpSocket::bind(listen_on);
    let socket;
    match attempt {
        Ok(sock) => {
            println!("Bound socket to {}", listen_on);
            socket = sock;
        }
        Err(err) => panic!("Could not bind: {}", err),
    }
    socket
}

pub fn listen(listen_on: net::SocketAddr) {
    let socket = socket(listen_on);
    read_message(&socket)
}

fn main() {
    // Start the server on port 9898
    let ip = net::Ipv4Addr::new(192, 168, 1, 77);
    let listen_addr = net::SocketAddrV4::new(ip, 9898);
    listen(net::SocketAddr::V4(listen_addr));
}
