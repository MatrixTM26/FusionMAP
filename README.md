# FusionMAP
## Nmap Scripting Engine: Network and Web Security Audit

Author  : MatrixTM26
Version : 3.0
License : Same as Nmap -- https://nmap.org/book/man-legal.html

---

## Overview

Four NSE scripts for auditing web, SSH, DNS, and general service
security.  Version 3.0 eliminates all ssl-failed and http.socket
errors by replacing Nmap's http library with raw nmap.new_socket()
connections in every script that communicates over HTTP or HTTPS.

Root cause of previous errors:

    "ssl failed: TIMEOUT" on port 5800
    "http.request socket error"
    "http.head socket error"

    All caused by Nmap's http library deciding whether to use TLS
    based on port.service, which is unreliable without -sV.
    Port 5800 (VNC-HTTP) is plain HTTP but the library attempted
    TLS.  Port 443 is TLS but the library sometimes skipped it.

Fix applied in v3.0:

    Removed require "http" from http-security-audit.nse and
    service-vuln-scan.nse.  All HTTP communication now uses
    raw nmap.new_socket() with explicit ssl:set_option("ssl",true)
    only where needed.  TLS detection logic:

      1. Try plain HTTP first (safe for all ports).
      2. If plain succeeds, done -- never attempt TLS.
      3. If plain fails and port is 443 or 8443, retry with TLS.
      4. All other ports (5800, 8080, 8888, etc.) stay plain HTTP.

---

## Files

    http-security-audit.nse   HTTP/HTTPS security header audit
    ssh-security-audit.nse    SSH algorithm and version audit
    dns-zone-audit.nse        DNS zone transfer and config audit
    service-vuln-scan.nse     Service fingerprint and CVE scanner

---

## Requirements

    nmap >= 7.80
    Lua 5.3 (bundled with Nmap)
    LuaSocket (bundled with Nmap)
    OpenSSL support in Nmap (for TLS targets; most builds include it)

---

## Installation

    sudo cp *.nse /usr/share/nmap/scripts/
    sudo nmap --script-updatedb

Verify installation:

    nmap --script-help http-security-audit
    nmap --script-help ssh-security-audit

---

## Script Reference

------------------------------------------------------------------------
### http-security-audit.nse
------------------------------------------------------------------------

Audits HTTP or HTTPS response headers for missing or misconfigured
security controls.  Works on all HTTP ports without generating
ssl-failed errors.

    nmap -p 80             --script http-security-audit <target>
    nmap -p 443            --script http-security-audit <target>
    nmap -p 5800           --script http-security-audit <target>
    nmap -p 80,443,8080    --script http-security-audit <target>
    nmap -p 443            --script http-security-audit \
         --script-args http-security-audit.path=/admin <target>
    nmap -p 8443           --script http-security-audit \
         --script-args http-security-audit.timeout=15 <target>

Script arguments:

    http-security-audit.path      Path to request (default: /)
    http-security-audit.timeout   Timeout in seconds (default: 10)

Checks performed:

    Security headers (11 total, scored 0-100):
      Strict-Transport-Security    weight 15
      Content-Security-Policy      weight 20
      X-Frame-Options              weight 10
      X-Content-Type-Options       weight 10
      Referrer-Policy              weight  8
      Permissions-Policy           weight  8
      X-XSS-Protection             weight  5
      Cross-Origin-Opener-Policy   weight  7
      Cross-Origin-Resource-Policy weight  7
      Cache-Control                weight  5
      Clear-Site-Data              weight  5

    Deep validation:
      HSTS max-age minimum (31536000), includeSubDomains
      CSP unsafe-inline, unsafe-eval, wildcard detection
      X-Frame-Options valid values (DENY, SAMEORIGIN)
      X-Content-Type-Options must be "nosniff"

    Additional checks:
      Cookie flags: Secure, HttpOnly, SameSite
      CORS wildcard: Access-Control-Allow-Origin: *
      Clickjacking: X-Frame-Options or CSP frame-ancestors
      HSTS on plain HTTP (misconfiguration)
      Server/technology header disclosure

    Output:
      Security score 0-100 with letter grade A-F
      List of present headers
      List of missing headers
      Warnings for misconfigurations
      Info disclosure findings
      Prioritized recommendations

Sample output:

    PORT    STATE SERVICE
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
    |     Cookie 'session': missing Secure, missing SameSite
    |   Info Disclosure:
    |     Server: Apache/2.4.51 (Ubuntu)
    |     X-Powered-By: PHP/7.4.3
    |   Recommendations:
    |     Add Content-Security-Policy (highest priority)
    |_    Enable HSTS: max-age=31536000; includeSubDomains

------------------------------------------------------------------------
### ssh-security-audit.nse
------------------------------------------------------------------------

Audits SSH banner and KEXINIT packet for weak algorithms and
outdated software.

    nmap -p 22 --script ssh-security-audit <target>
    nmap -p 22 --script ssh-security-audit \
         --script-args ssh-security-audit.timeout=15 <target>
    nmap -p 22 --script ssh-security-audit 192.168.1.0/24

Script arguments:

    ssh-security-audit.timeout   Timeout in seconds (default: 10)

Banner reader fix (v2.0+):

    Previous behavior: loop receive_bytes(1) per character.
    Problem: if first byte delayed, entire timeout burns empty.

    New behavior: single blocking receive_bytes(256).
    Waits until any data arrives then returns the full chunk.
    Fallback: if server is silent, send client banner first
    (RFC 4253 permits client-first) then read again.

Checks performed:

    Banner:
      SSH protocol version (SSHv1 detection)
      OpenSSH version CVE mapping (< 7.x critical, < 8.x warning)
      Dropbear and Cisco SSH detection

    KEXINIT algorithms:
      KEX: DH Group1, SHA1-based KEX
      Ciphers: RC4, 3DES, DES, all CBC-mode variants
      MACs: MD5, SHA1, truncated variants, UMAC-32
      Host keys: DSA, RSA-SHA1, NIST curves
      Compression: zlib (CRIME-like risk)

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
    |     [X] hmac-md5   WEAK: HMAC-MD5 -- MD5 is not secure for MAC
    |     [X] aes128-cbc WARNING: AES-CBC -- susceptible to BEAST
    |   Risk Level: MEDIUM (3 issue(s))
    |   Hardening Tips:
    |     Allow only: chacha20-poly1305, aes256-gcm, aes128-gcm
    |_    Use ETM MACs: hmac-sha2-256-etm, hmac-sha2-512-etm

------------------------------------------------------------------------
### dns-zone-audit.nse
------------------------------------------------------------------------

Tests DNS server security.

    nmap -p 53 --script dns-zone-audit <target>
    nmap -p 53 --script dns-zone-audit \
         --script-args dns-zone-audit.domain=example.com ns1.example.com

Script arguments:

    dns-zone-audit.domain   Domain for AXFR and email security checks

Checks performed:

    Zone Transfer (AXFR) via TCP
    Open Resolver (resolves external domains)
    DNS version disclosure via version.bind TXT/CHAOS
    DNSSEC presence
    SPF record: v=spf1, softfail vs hardfail, +all detection
    DMARC policy: none / quarantine / reject
    DKIM selector enumeration (6 common selectors)

------------------------------------------------------------------------
### service-vuln-scan.nse
------------------------------------------------------------------------

Fingerprints service banners and matches against a local CVE database.
Uses raw sockets only.

    nmap -sV --script service-vuln-scan <target>
    nmap -p 21,22,80,443,3306,6379 --script service-vuln-scan <target>
    nmap --script service-vuln-scan \
         --script-args service-vuln-scan.timeout=10 <target>

Script arguments:

    service-vuln-scan.timeout   Timeout in seconds (default: 8)

Services and CVEs:

    Port 22  OpenSSH
             CVE-2016-6210  username enumeration (7.2)
             CVE-2018-15473 username enumeration (7.6)
             CVE-2021-28041 double-free ssh-agent (8.5)
             CVE-2023-25136 double-free pre-auth (9.1)
             + 5 more

    Port 80/443  Apache httpd
             CVE-2021-41773 path traversal and RCE (2.4.50)
             CVE-2021-40438 mod_proxy SSRF (2.4.48)
             CVE-2023-25690 request smuggling (2.4.56)
             + 2 more

    Port 80/443  nginx
             CVE-2017-7529  integer overflow range filter
             CVE-2018-16843 HTTP/2 DoS
             CVE-2019-9511  HTTP/2 Data Dribble DoS

    Port 21  vsftpd
             CVE-2011-2523  BACKDOOR (version 2.3.4 only)
             CVE-2008-2375  remote DoS

    Port 21  ProFTPD
             CVE-2015-3306  arbitrary file read/write CVSS 10.0
             CVE-2010-4221  heap overflow RCE

    Port 3306  MySQL / MariaDB
             CVE-2016-6662  arbitrary config file creation CVSS 10.0
             CVE-2012-2122  auth bypass timing attack

    Port 6379  Redis
             CVE-2021-29477  heap overflow RESP parser
             CVE-2022-24834  heap overflow Lua cjson

    Port 23  Telnet
             INSECURE-PROTOCOL  plaintext credential exposure

    Additional runtime checks:
             FTP anonymous login (port 21)
             Redis unauthenticated PING (port 6379)

---

## Combined Usage

Full audit of a single host:

    nmap -sV -p- \
         --script "http-security-audit,ssh-security-audit,dns-zone-audit,service-vuln-scan" \
         -oN audit.txt <target>

Fast web audit:

    nmap -p 80,443,8080,8443 \
         --script "http-security-audit,service-vuln-scan" <target>

Network-wide SSH audit:

    nmap -p 22 --script ssh-security-audit 192.168.1.0/24

Save as XML for parsing:

    nmap --script service-vuln-scan -oX results.xml <target>

---

## Changelog

v3.0
    - Removed require "http" from http-security-audit.nse and
      service-vuln-scan.nse.  All HTTP/HTTPS connections now use
      raw nmap.new_socket() with manual TLS control.
    - TLS auto-detection: plain first, SSL retry only for 443/8443.
      Eliminates ssl-failed on ports like 5800 (VNC-HTTP), 8080,
      and http.socket errors on port 443 without -sV.
    - http-security-audit: full HTTP response parser built-in,
      no dependency on external libraries.

v2.0
    - Fixed ssh-security-audit "No SSH banner received" error.
      Replaced per-byte receive loop with blocking receive_bytes(256)
      plus client-first fallback (RFC 4253).
    - All output and messages translated to English.
    - Author set to MatrixTM26.
    - Default timeout increased from 5s to 8-10s.

v1.0
    - Initial release.

---

## Disclaimer

These scripts are for authorized security testing only.
Use only on systems you own or have explicit written permission
to test.  Unauthorized use may violate applicable laws.
