# D-Link DCS-930L IP Camera Vulnerability Report

## Target Information

| Field | Value |
|-------|-------|
| Device | D-Link DCS-930L REVA IP Camera |
| Firmware | v1.16.04 / mydlink 2.1.0-b41 |
| Build Date | 2016-09-09 |
| Architecture | MIPS 32-bit LE (mipsel), MIPS-II |
| SoC | Ralink RT3050 |
| C Library | uClibc 0.9.28 |
| Binary: alphapd | MD5: b17cd8a0965c0f131b57e429a9165f6e |
| Binary: lanconfig | MD5: 274aa92531bf44348717c5f7c373c166 |

## Vulnerability Summary

| ID | Vulnerability | Severity | Auth | Binary | Evidence |
|----|---------------|----------|------|--------|----------|
| V6 | Unauth RCE via LANAP UDP command injection | Critical | None | lanconfig | E6-runtime-confirmed (original binary) |
| V1 | Unauth RCE via HTTP Currenttime command injection | Critical | None* | alphapd | E6-runtime-confirmed (patched binary) |
| V4 | Auth bypass when AdminID/AdminPassword empty | Critical | None | alphapd | E4-static-decoded |

*V1 auth bypass requires empty admin credentials (factory default)

## Files

```
DCS-930L/
├── README.md                          # This file
├── poc_v6_lanconfig_udp_rce.py         # V6 PoC (original binary confirmed)
├── poc_v1_currenttime_rce.py           # V1 PoC
├── evidence/
│   ├── v6_strace_original_binary.txt   # V6 strace evidence (original unmodified binary)
│   ├── v1_strace_patched_binary.txt    # V1 strace evidence
│   ├── alphapd_patch_details.md         # V1 3-NOP patch documentation (hardware bypass, not security)
│   ├── ida_changeid_decompilation.txt   # V6 IDA decompilation of landap_change_idpassword
│   └── ida_v1flow_decompilation.txt     # V1 IDA decompilation of websKernalParameter
```

## Disclosure

These vulnerabilities were discovered during authorized firmware security research.
Reported for educational and defensive purposes only.
