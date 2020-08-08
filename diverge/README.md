## Diverge

Small utility used for diffing userland execution traces between Barbervisor and `windbg`. Was used in early testing to confirm register states matched execution in Barbervisor vs the same in windbg.

Kept in the repo for legacy purposes.

## Windbg trace

Windbg trace was dumped via the slowest possible mechanic.

Trace until hit `0x7ff77393b375`.

```
.logopen single_step.txt
Opened log file 'single_step.txt'
0:000> r; t; z(@rip != 0x7ff77393b375)
```
