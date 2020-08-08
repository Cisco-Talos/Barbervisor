### Check address from snapshot

Utility to dump the module and instruction at a given address from the current snapshot. 

```
cargo run --release -- 0xfffff8027ba0d1ef
```

```
ntoskrnl.exe!KiSystemCall64Shadow+0x2f (ntoskrnl.exe+0xa0d1ef) 0xfffff8027ba0d1ef: push qword ptr gs:[0x9010]
```

## Notes

PDB listing is needed in `./versions/win10.system32` as a mapping of modules to their hash.

Example:

```
user32.pdb HASH
win32k.pdb HASH
win32kbase.pdb HASH
win32kfull.pdb HASH
win32u.pdb HASH
```
