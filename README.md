# LuaNetSec NSE Scripts
## Nmap Scripting Engine -- Network & Web Security Audit

Author  : MatrixTM26
Version : 2.0 (fixed)
License : Same as Nmap -- https://nmap.org/book/man-legal.html

---

## Files

    http-security-audit.nse   Web security header audit (HTTP + HTTPS)
    ssh-security-audit.nse    SSH algorithm and version audit
    dns-zone-audit.nse        DNS zone transfer and configuration audit
    service-vuln-scan.nse     Service fingerprint and CVE scanner

---

## Requirements

    nmap >= 7.80
    Lua 5.3+ (bundled with Nmap)
    LuaSocket (bundled with Nmap)

---

## Installation

    sudo cp *.nse /usr/share/nmap/scripts/
    sudo nmap --script-updatedb

---

## Usage

### http-security-audit.nse

Audits HTTP/HTTPS response headers for missing or misconfigured
security controls. Works on all HTTP ports including non-standard
ports (5800, 8080, 8888, etc.) without triggering TLS on plain
HTTP connections.

    nmap -p 80,443 --script http-security-audit <target>
    nmap -p 5800   --script http-security-audit <target>
    nmap -p 443    --script http-security-audit \
         --script-args http-security-audit.path=/login <target>
    nmap -p 8443   --script http-security-audit \
         --script-args http-security-audit.timeout=15 <target>

Script arguments:

    http-security-audit.path      URL path to request (default: /)
    http-security-audit.timeout   Timeout in seconds (default: 10)

Checks performed:
    - Strict-Transport-Security (HSTS)
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - Referrer-Policy
    - Permissions-Policy
    - X-XSS-Protection
    - Cross-Origin-Opener-Policy
    - Cross-Origin-Resource-Policy
    - Cache-Control
    - Clear-Site-Data
    - Cookie flags (Secure, HttpOnly, SameSite)
    - CORS wildcard (Access-Control-Allow-Origin: *)
    - Server/technology header disclosure
    - Security score 0-100 with letter grade (A-F)

Sample output:

    PORT   STATE SERVICE
    443/tcp open  https
    | http-security-audit:
    |   Protocol: HTTPS (TLS)
    |   HTTP Status: 200
    |   Security Score: 55/100 -- Grade: D
    |   Headers Present:
    |     [PRESENT] X-Frame-Options                    SAMEORIGIN
    |     [PRESENT] X-Content-Type-Options             nosniff
    |   Headers Missing:
    |     [MISSING] Strict-Transport-Security          HSTS -- prevents HTTP downgrade
    |     [MISSING] Content-Security-Policy            CSP -- prevents XSS and injection
    |   Warnings:
    |     DANGER: No clickjacking protection
    |   Info Disclosure:
    |     Server: Apache/2.4.51 (Ubuntu)
    |_  Recommendations: Add Content-Security-Policy to prevent XSS

---

### ssh-security-audit.nse

Audits SSH server banner and KEXINIT packet to identify weak
cryptographic algorithms and outdated software versions.

Fixed in v2.0: banner reader now uses a single blocking
receive_bytes(256) call instead of per-byte reads, which
resolves "No SSH banner received" on slow or proxy servers.
Also handles servers that wait for a client banner first
(client-first RFC 4253 mode).

    nmap -p 22 --script ssh-security-audit <target>
    nmap -p 22 --script ssh-security-audit \
         --script-args ssh-security-audit.timeout=15 <target>
    nmap -p 22 --script ssh-security-audit 192.168.1.0/24

Script arguments:

    ssh-security-audit.timeout    Timeout in seconds (default: 10)

Checks performed:
    - SSH protocol version (SSHv1 detection)
    - OpenSSH / Dropbear version CVE mapping
    - KEX algorithms (detects DH Group1, SHA1-based)
    - Encryption algorithms (detects RC4, 3DES, DES, CBC-mode)
    - MAC algorithms (detects MD5, SHA1, truncated variants)
    - Host key types (detects DSA, RSA-SHA1, NIST curves)
    - Compression (detects zlib)

Sample output:

    PORT   STATE SERVICE
    22/tcp open  ssh
    | ssh-security-audit:
    |   SSH Banner: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10
    |   Server Info:
    |     Protocol: SSH-2.0
    |     WARNING: OpenSSH 7.2 -- consider upgrading to 8.x+
    |   Encryption Algorithms: aes128-ctr,aes192-ctr,aes256-ctr,...
    |   Security Issues:
    |     [X] hmac-md5    WEAK: HMAC-MD5 -- MD5 is not secure for MAC
    |     [X] aes128-cbc  WARNING: AES-CBC -- susceptible to BEAST attack
    |   Risk Level: MEDIUM (3 issue(s))
    |_  Hardening Tips: Allow only: chacha20-poly1305, aes256-gcm, ...

---

### dns-zone-audit.nse

Tests DNS server security including zone transfer attempts,
open resolver detection, version disclosure, and email
security records.

    nmap -p 53 --script dns-zone-audit <target>
    nmap -p 53 --script dns-zone-audit \
         --script-args dns-zone-audit.domain=example.com ns1.example.com

Script arguments:

    dns-zone-audit.domain    Domain name for AXFR and email checks

Checks performed:
    - Zone Transfer (AXFR) via TCP
    - Open Resolver detection
    - DNS version disclosure (version.bind)
    - DNSSEC status
    - SPF record validation
    - DMARC policy check
    - DKIM selector enumeration

---

### service-vuln-scan.nse

Fingerprints service banners and matches versions against a
local CVE database. Supports plain HTTP, HTTPS, and raw TCP
banner grabbing.

Fixed in v2.0: TLS detection now uses port.version.service_tunnel
(set by nmap -sV) as primary source and only falls back to port
number heuristics for ports 443 and 8443. This prevents TLS
handshake attempts on plain-HTTP ports such as 5800 (VNC HTTP).

    nmap -sV --script service-vuln-scan <target>
    nmap -p 21,22,80,443,3306,6379 --script service-vuln-scan <target>
    nmap --script service-vuln-scan \
         --script-args service-vuln-scan.timeout=10 <target>

Script arguments:

    service-vuln-scan.timeout    Timeout in seconds (default: 8)

Services covered:
    - OpenSSH (port 22)
    - Apache httpd (port 80, 443, 8080, 8443)
    - nginx (port 80, 443, 8080, 8443)
    - vsftpd (port 21) -- includes backdoor CVE-2011-2523 detection
    - ProFTPD (port 21)
    - MySQL / MariaDB (port 3306)
    - Redis (port 6379) -- includes unauthenticated access check
    - Telnet (port 23)
    - FTP anonymous login (port 21)

Sample output:

    PORT    STATE SERVICE
    21/tcp  open  ftp
    | service-vuln-scan:
    |   Banner: 220 (vsFTPd 2.3.4)
    |   Service: vsftpd
    |   Version: 2.3.4
    |   Vulnerabilities:
    |     [CRITICAL] CVE-2011-2523 (CVSS 10.0) -- BACKDOOR: ':)' in username
    |   Risk Level: CRITICAL (max CVSS: 10.0)
    |   CVEs / Issues: CVE-2011-2523
    |_  Action: Update the service or apply mitigations immediately

---

## Combining Scripts

Run all scripts against a single target:

    nmap -sV -p- \
         --script "http-security-audit,ssh-security-audit,dns-zone-audit,service-vuln-scan" \
         -oN full_audit.txt <target>

Fast web audit:

    nmap -p 80,443,8080,8443 \
         --script "http-security-audit,service-vuln-scan" <target>

Network-wide SSH audit:

    nmap -p 22 --script ssh-security-audit 192.168.1.0/24

Save results as XML:

    nmap --script service-vuln-scan -oX results.xml <target>

---

## Changelog

v2.0
    - Fixed: ssh-security-audit returns "No SSH banner received" on
      slow servers. New read_ssh_banner() uses blocking receive_bytes(256)
      with client-first fallback instead of per-byte loop.
    - Fixed: service-vuln-scan and http-security-audit trigger SSL
      timeout on non-TLS ports (e.g. 5800 VNC-HTTP). TLS detection
      now checks port.version.service_tunnel first.
    - Fixed: http.head() timeout on port 443 when running without -sV.
      do_request() now correctly forces plain HTTP on non-TLS ports.
    - Changed: all output and messages are in English.
    - Changed: author set to MatrixTM26.
    - Changed: default timeout increased from 5s to 8-10s.

v1.0
    - Initial release.

---

## Disclaimer

These scripts are intended for authorized penetration testing and
security auditing only. Use only on systems you own or have explicit
written permission to test. Unauthorized use may violate laws
including but not limited to the Computer Fraud and Abuse Act (CFAA)
and equivalent legislation in your jurisdiction.
