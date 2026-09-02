# alphapd Binary Patch Details for QEMU Verification

## Overview

The V1 vulnerability (HTTP Currenttime command injection) was dynamically verified
on a patched version of `alphapd`. The patches bypass a **hardware dependency**
(`/dev/gpio` RTC device) that QEMU user-mode cannot emulate — they do **NOT**
bypass any security mechanism.

On real DCS-930L hardware, these patches are **not needed** because `/dev/gpio`
works normally and `getSysInfoBuffer(4)` returns a valid stored date.

## Binary Information

| Property | Value |
|----------|-------|
| Original MD5 | b17cd8a0965c0f131b57e429a9165f6e |
| Patched MD5 | 251b63c08b49386478036f21f232d2af |
| Architecture | MIPS 32-bit LE (mipsel), MIPS-II |
| Patched binary | `alphapd.patched_v2` |

## Patch Details (3 NOP patches)

### Patch 1: websTestVar gate bypass

| Property | Value |
|----------|-------|
| Address | `0x4137c4` |
| Original bytes | `0x1440001d` — `bnez $v0, loc_41383C` (branch if Currenttime var NOT present) |
| Patched bytes | `0x1000001d` — `b loc_41383C` (unconditional branch, always process Currenttime) |

**Purpose**: The original code checks whether the `Currenttime` query parameter
is present in the HTTP request via `websTestVar()`. If absent, it skips
processing. This is a **functional gate**, not a security check. In QEMU the
parameter IS present in our test request, but the `bnez` instruction was patched
to `b` (unconditional) to ensure the code path is always reached during testing.

**Security impact**: None. This gate only controls whether the `Currenttime`
parameter is processed. On real hardware with a valid HTTP request containing
`Currenttime=...`, the original `bnez` passes normally.

---

### Patch 2: Year comparison bypass

| Property | Value |
|----------|-------|
| Address | `0x413934` |
| Original bytes | `0x1630ffa5` — `bne $s1, $s0, loc_4137CC` (branch if year != stored_year) |
| Patched bytes | `0x00000000` — `nop` (no operation, skip comparison) |

**Purpose**: After reading the current year via `localtime()` and the device's
stored year via `getSysInfoBuffer(4)`, the code compares them. If they differ,
it exits the function without calling `doSystem()`.

The issue: `getSysInfoBuffer(4)` reads from `/dev/gpio` (hardware RTC). In QEMU,
`/dev/gpio` is not emulated → `ioctl(fd, 0x23880, ...)` returns `ENOTTY` →
`getSysInfoBuffer` returns empty/0 → stored_year = 0. The current year (2026)
does not equal 0, so the branch exits.

**Security impact**: None. On real hardware, `getSysInfoBuffer(4)` returns the
device's stored date (e.g., "2026-09-02"), and the year comparison passes
normally when the Currenttime parameter contains a valid future date.

---

### Patch 3: Month/day comparison bypass

| Property | Value |
|----------|-------|
| Address | `0x41393c` |
| Original bytes | `0x10400055` — `beqz $v0, loc_413A94` (branch if month/day check fails) |
| Patched bytes | `0x00000000` — `nop` (no operation, skip comparison) |

**Purpose**: Similar to Patch 2, this checks whether the month and day from the
Currenttime parameter match the stored date. In QEMU, the stored date is empty
(0/0), so the comparison always fails and the code exits.

**Security impact**: None. On real hardware with a valid stored date, this
comparison passes when the Currenttime parameter contains a matching date.

## QEMU Limitation Details

The `getSysInfoBuffer()` function in `alphapd`:

```c
// getSysInfoBuffer @ 0x410f38 (local function in alphapd)
int fd = open("/dev/gpio", O_RDONLY);
ioctl(fd, 0x23880, buffer);  // reads SysInfo struct from hardware
close(fd);
```

QEMU user-mode emulation cannot emulate custom character devices like `/dev/gpio`:
- `open("/dev/gpio")` succeeds (the device node is created by `rcS` via `mknod`)
- `ioctl(fd, 0x23880, ...)` returns `-1 ENOTTY (Not a tty)` because QEMU doesn't
  know how to handle this custom ioctl
- Result: `getSysInfoBuffer` returns empty/zero data

The `/dev/gpio` device is created at boot in `/etc_ro/rcS`:
```sh
mknod /dev/gpio c 252 0
```

## strace Evidence

```
# QEMU attempting to read /dev/gpio (fails with ENOTTY):
1021 open("/dev/gpio",O_RDONLY) = 4
1021 ioctl(4,0x23880,0x2b2abcd8) = -1 errno=25 (Not a tty)
1021 close(4) = 0
```

## Conclusion

These 3 patches are **emulation environment workarounds**, not security bypasses:
- No authentication mechanism was patched
- No input validation/filter was removed
- No security check was disabled
- The vulnerable sink (`doSystem("date -s %s &", websGetVar("Currenttime"))`)
  exists in the original binary and is the actual vulnerability

The patches simply make the vulnerable code path reachable in the absence of
`/dev/gpio` hardware, which only affects the QEMU test environment.
