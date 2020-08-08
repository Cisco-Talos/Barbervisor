# TFTP Server

Custom TFTP server that is automatically started during `cargo run` from the main repo. Should be 
modified to point to the IP address that it should bind to that is on the same network as the 
hardware that the hypervisor is running on. Defaults to running on port `9898`.

Uses the current snapshot found in `../snapshot/snapshot.[dmp|phys]` to aid in analysis.

## Custom commands

Two additional features have been added to the TFTP server to help the hypervisor:

* `SNAPSHOT_translate_0xc3000_0x120000`: Translates the guest virtual address (second) using the CR3 (first)
* `SNAPSHOT_page_0x2000`: Returns the page-aligned physical page located at the given guest physical address

## Manually run

```
cargo run --release
```
