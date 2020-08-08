# Parse trace

Parses the returned trace from the hypervisor into a readable format. Relies on `../snapshot/snapshot.[dmp|phys]` for discovering modules and the instruction.

```
cargo run --release                  # Parses the ../tftp-server/test.trace
cargo run --release -- yourtrace.txt # Parses the given trace
```

## Output

```
cr3: 0x498e5000 cs: 0x33
TEB PEB: 0x496b712000
{
    0x7ffda8840000..0x7ffda886a000: "GDI32.dll",
    0x7ffda7a50000..0x7ffda7b25000: "OLEAUT32.dll",
    ...
}

User modules hash: 0x25ff119b564000
DTB (kernel_cr3) [0x1aaaa0]: 0x1aa000
Kernel cr3: 0x1aa000
DTB (kernel_cr3) [0x1aaaa0]: 0x1aa000
KCR3: 1aa000
KDBG [0x2cd19444]: 0xf8027b000000
KDBG: f8027b000000
Found PsLoadedModuleList: 0xc2a4f0
PLML offset: c2a4f0
{
    0xfffff8027f520000..0xfffff8027f560000: "Wof.sys",
    0xfffff8027ebf0000..0xfffff8027ecd1000: "CI.dll",
    0xfffff8027ee80000..0xfffff8027ee93000: "WDFLDR.SYS",
    0xfffff80281570000..0xfffff80281595000: "HDAudBus.sys",
    0xfffff8027ef70000..0xfffff8027f03c000: "ACPI.sys",
    0xfffff802798a0000..0xfffff802798c5000: "bowser.sys",
    ...
}

...
[2433] verifier.dll+0x000021bd, (0x7ffcea4e21bd) 0x7ffcea4e21bd: mov rdx, rbx
[2434] verifier.dll+0x000021c0, (0x7ffcea4e21c0) 0x7ffcea4e21c0: or rcx, 0xffffffffffffffff
[2435] verifier.dll+0x000021c4, (0x7ffcea4e21c4) 0x7ffcea4e21c4: call qword ptr [rip + 0x28255]
[2436] ntdll.dll!ZwAllocateVirtualMemory+0x0, (ntdll.dll+0x9b980) 0x7ffd0ffcb980: mov r10, rcx
[2437] ntdll.dll!ZwAllocateVirtualMemory+0x3, (ntdll.dll+0x9b983) 0x7ffd0ffcb983: mov eax, 0x18
[2438] ntdll.dll!ZwAllocateVirtualMemory+0x8, (ntdll.dll+0x9b988) 0x7ffd0ffcb988: test byte ptr [0x7ffe0308], 1
[2439] ntdll.dll!ZwAllocateVirtualMemory+0x10, (ntdll.dll+0x9b990) 0x7ffd0ffcb990: jne 0x7ffd0ffcb995
[2440] ntdll.dll!ZwAllocateVirtualMemory+0x12, (ntdll.dll+0x9b992) 0x7ffd0ffcb992: syscall 
[2441] ntoskrnl.exe!KiSystemCall64Shadow+0x0, (ntoskrnl.exe+0xa0d1c0) 0xfffff8027ba0d1c0: swapgs 
[2442] ntoskrnl.exe!KiSystemCall64Shadow+0x3, (ntoskrnl.exe+0xa0d1c3) 0xfffff8027ba0d1c3: mov qword ptr gs:[0x9010], rsp
[2443] ntoskrnl.exe!KiSystemCall64Shadow+0xc, (ntoskrnl.exe+0xa0d1cc) 0xfffff8027ba0d1cc: mov rsp, qword ptr gs:[0x9000]
[2444] ntoskrnl.exe!KiSystemCall64Shadow+0x15, (ntoskrnl.exe+0xa0d1d5) 0xfffff8027ba0d1d5: bt dword ptr gs:[0x9018], 1
[2445] ntoskrnl.exe!KiSystemCall64Shadow+0x1f, (ntoskrnl.exe+0xa0d1df) 0xfffff8027ba0d1df: jb 0xfffff8027ba0d1e4
[2446] ntoskrnl.exe!KiSystemCall64Shadow+0x24, (ntoskrnl.exe+0xa0d1e4) 0xfffff8027ba0d1e4: mov rsp, qword ptr gs:[0x9008]
[2447] ntoskrnl.exe!KiSystemCall64Shadow+0x2d, (ntoskrnl.exe+0xa0d1ed) 0xfffff8027ba0d1ed: push 0x2b
[2448] ntoskrnl.exe!KiSystemCall64Shadow+0x2f, (ntoskrnl.exe+0xa0d1ef) 0xfffff8027ba0d1ef: push qword ptr gs:[0x9010]
[2449] ntoskrnl.exe!KiSystemCall64Shadow+0x37, (ntoskrnl.exe+0xa0d1f7) 0xfffff8027ba0d1f7: push r11
[2450] ntoskrnl.exe!KiSystemCall64Shadow+0x39, (ntoskrnl.exe+0xa0d1f9) 0xfffff8027ba0d1f9: push 0x33
[2451] ntoskrnl.exe!KiSystemCall64Shadow+0x3b, (ntoskrnl.exe+0xa0d1fb) 0xfffff8027ba0d1fb: push rcx
[2452] ntoskrnl.exe!KiSystemCall64Shadow+0x3c, (ntoskrnl.exe+0xa0d1fc) 0xfffff8027ba0d1fc: mov rcx, r10
[2453] ntoskrnl.exe!KiSystemCall64Shadow+0x3f, (ntoskrnl.exe+0xa0d1ff) 0xfffff8027ba0d1ff: sub rsp, 8
[2454] ntoskrnl.exe!KiSystemCall64Shadow+0x43, (ntoskrnl.exe+0xa0d203) 0xfffff8027ba0d203: push rbp
[2455] ntoskrnl.exe!KiSystemCall64Shadow+0x44, (ntoskrnl.exe+0xa0d204) 0xfffff8027ba0d204: sub rsp, 0x158
[2456] ntoskrnl.exe!KiSystemCall64Shadow+0x4b, (ntoskrnl.exe+0xa0d20b) 0xfffff8027ba0d20b: lea rbp, [rsp + 0x80]
[2457] ntoskrnl.exe!KiSystemCall64Shadow+0x53, (ntoskrnl.exe+0xa0d213) 0xfffff8027ba0d213: mov qword ptr [rbp + 0xc0], rbx
[2458] ntoskrnl.exe!KiSystemCall64Shadow+0x5a, (ntoskrnl.exe+0xa0d21a) 0xfffff8027ba0d21a: mov qword ptr [rbp + 0xc8], rdi
```
