# Barbervisor

Intel x86 bare metal hypervisor for researching snapshot fuzzing ideas. 

The blog describing the developement of the tool can be found [here](https://blog.talosintelligence.com/2020/08/barbervisor.html)

## Building

Ensure `i586-pc-windows-msvc` and `x86_64-pc-windows-msvc` toolchains are installed and running nightly Rust.

```
> rustup target add i586-pc-windows-msvc
> rustup target add x86_64-pc-windows-msvc 

> rustup toolchain list
nightly-x86_64-pc-windows-msvc (default)
```

Download [LLVM](https://releases.llvm.org/download.html) and have `lld-link` in the path.
Download [NASM](https://nasm.us/) and have `nasm` in the path.

Change the IP address in `tftp-server/src/main` to bind to the wanted network address.

```
> cargo run
```

## Snapshots

Snapshots are currently gathered from VirtualBox. 

After snapshotting from VirtualBox, place the result of `writecore` at `snapshot/snapshot.dmp` and the result of `.pgmphystofile` at `snapshot/snapshot.phys`. These paths are hard coded and are required for most of the utilities.

## Deploying

Copy `barberslice.boot` and `barberslice.kern` to a TFTPD server folder configured for PXE booting. Also set the PXE boot filename to `barberslice.boot` in your DHCP server.

## Bochs

The kernel can be tested in [Bochs](http://bochs.sourceforge.net/) before testing on bare metal.

```
bochs -q -f emu/bochsrc
```

Be sure to change the following lines of the `bochsrc` to point to your local Bochs install:

```
romimage: file="C:\Users\user\git\bochs\bios\BIOS-bochs-latest", address=0x0, options=none
vgaromimage: file="C:\Users\user\git\bochs\bios\VGABIOS-lgpl-latest"
ata0-master: type=cdrom, path="C:\Users\user\git\barberslice\ipxe\src\bin\ipxe.iso", status=inserted
e1000: enabled=1, mac=52:54:00:12:34:56, ethmod=vnet, ethdev="C:\Users\user\git\barberslice\emu"
```

## iPXE

iPXE build is included if wanted to test in Bochs using PXE.

On linux:

```
sudo apt-get install liblzma liblzma-dev isolinux mkisofs
git clone https://github.com/ipxe/ipxe
cd ipxe/src
make bin/ipxe.iso EMBED=../../emu/boot.ipxe
```

## Utilities

* `check_address`: Return the module+offset and instruction for a given address from the current snapshot
* `corpgen`: Generates serialized corpus for shipping to the kernel
* `coverage`: Dump `module+offset` coverage file to load into [lighthouse](https://github.com/gaasedelen/lighthouse) 
* `diverage`: Legacy utility used to diff a `windbg` single step trace and a trace dumped from Barberslice
* `find_input`: Return all generated files that hit a given address
* `parse_trace`: Parses the trace format sent from the hypervisor into a human readable form
* `pci-ids-parser`: Parser for dumping PCI information that was going to be added to the kernel (but never was)
* `snapshot`: Parses the VirtualBox core dump file and dumps the register state for the kernel to use. 
* `tftp-server`: Custom TFTP server for communicating with the hypervisor

## Docs

The main kernel docs can be found:

```
cd kernel
cargo doc --open
```

The utilities also have READMEs giving a high level overview of what the tool is used for.
