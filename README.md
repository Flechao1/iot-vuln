# iot-vuln
iot漏洞搜集

## 目录

- [cve-pocs/](./cve-pocs/) — 三枚已分配 CVE 编号的路由器命令注入漏洞 PoC 与分析
  - [CVE-2026-75360](./cve-pocs/CVE-2026-75360) — D-Link DIR-3040 预认证命令注入
  - [CVE-2026-75363](./cve-pocs/CVE-2026-75363) — Comfast CF-WR630AX `ntp_timezone` 命令注入
  - [CVE-2026-75364](./cve-pocs/CVE-2026-75364) — Comfast CF-WR630AX `update_interface_png` 命令注入

## D-Link DCS-930L IP Camera (fw v1.16.04 / mydlink 2.1.0-b41)

| ID | Vulnerability | Severity | Auth | Binary | Verified |
|----|---------------|----------|------|--------|----------|
| V6 | Unauth RCE via LANAP UDP command injection | Critical | None | lanconfig | ✅ Original binary |
| V1 | Unauth RCE via HTTP Currenttime command injection | Critical | None* | alphapd | ✅ Patched binary |

\* V1 auth bypass requires empty admin credentials (factory default)

See [DCS-930L/](DCS-930L/) for detailed analysis, PoC scripts, and evidence.
