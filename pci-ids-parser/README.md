### PCI ID Parser

Parses the PCI IDs from `pciutils` and dumps them in a linear format of `(VendorID, DeviceID) => Name`:

```
(0x10, 0x8139) => "Allied Telesis, Inc (Wrong ID):AT-2500TX V3 Ethernet",
(0x14, 0x7a00) => "Loongson Technology LLC:Hyper Transport Bridge Controller",
(0x14, 0x7a02) => "Loongson Technology LLC:APB (Advanced Peripheral Bus) Controller",
```

Results are in `pciids`. But if you want to rebuild:

```rust
cargo run --release
```

