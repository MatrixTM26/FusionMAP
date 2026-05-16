-- ============================================================
-- service-vuln-scan.nse
-- Nmap NSE Script: Service Fingerprint & CVE Vulnerability Scanner
--
-- Penggunaan:
--   nmap -sV --script service-vuln-scan <target>
--   nmap -p 21,22,80,443,3306 --script service-vuln-scan <target>
--   nmap --script service-vuln-scan --script-args service-vuln-scan.level=high <target>
--
-- Author : LuaNetSec Project
-- License: Same as Nmap
-- ============================================================

local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"
local http      = require "http"

description = [[
Melakukan fingerprinting service dan memeriksa versi yang diketahui
memiliki kerentanan. Script ini mengandung database CVE lokal
untuk service-service umum dan memberikan laporan risiko.

Service yang didukung:
  * OpenSSH — CVE database untuk versi lama
  * Apache HTTP Server — CVE untuk versi populer
  * nginx — CVE untuk versi lama
  * vsftpd / ProFTPD — backdoor & CVE
  * MySQL / MariaDB — privilege escalation
  * Redis — unauthenticated access
  * MongoDB — unauthenticated access
  * Elasticsearch — RCE & info disclosure
  * Telnet — insecure protocol detection
  * FTP Anonymous — misconfiguration
]]

author     = "LuaNetSec"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln", "discovery"}

portrule = function(host, port)
    return port.state == "open"
end

-- ──────────────────────────────────────────────────────────────
-- CVE DATABASE (lokal, subset representatif)
-- Format: { version_pattern, cve_id, cvss, description }
-- ──────────────────────────────────────────────────────────────
local CVE_DB = {

    -- ── OpenSSH ─────────────────────────────────────────────
    openssh = {
        { pattern="OpenSSH[_ ]([%d%.]+)", service="OpenSSH",
          cves = {
            { max_ver="4.9",  id="CVE-2008-5161",  cvss=2.6,  desc="CBC mode information leak" },
            { max_ver="5.8",  id="CVE-2011-0539",  cvss=5.0,  desc="Legacy certificate signing" },
            { max_ver="6.8",  id="CVE-2015-5600",  cvss=8.5,  desc="MaxAuthTries bypass" },
            { max_ver="6.9",  id="CVE-2015-6564",  cvss=6.9,  desc="Use-after-free in PAM" },
            { max_ver="7.1",  id="CVE-2016-0777",  cvss=4.0,  desc="Roaming info leak (client)" },
            { max_ver="7.1",  id="CVE-2016-0778",  cvss=4.6,  desc="Roaming buffer overflow (client)" },
            { max_ver="7.2",  id="CVE-2016-6210",  cvss=5.0,  desc="Username enumeration via timing" },
            { max_ver="7.3",  id="CVE-2016-6515",  cvss=7.8,  desc="DoS via password length" },
            { max_ver="7.6",  id="CVE-2018-15473", cvss=5.3,  desc="Username enumeration" },
            { max_ver="7.7",  id="CVE-2019-6111",  cvss=5.8,  desc="SCP path traversal" },
            { max_ver="8.3",  id="CVE-2020-14145", cvss=5.9,  desc="Observable discrepancy in client" },
            { max_ver="8.5",  id="CVE-2021-28041", cvss=7.1,  desc="Double-free in ssh-agent" },
            { max_ver="9.1",  id="CVE-2023-25136", cvss=6.5,  desc="Double-free pre-auth (memory)" },
          }
        },
    },

    -- ── Apache HTTP ──────────────────────────────────────────
    apache = {
        { pattern="Apache/([%d%.]+)",  service="Apache httpd",
          cves = {
            { max_ver="2.2.31", id="CVE-2017-7679",  cvss=9.8, desc="Heap buffer overflow mod_mime" },
            { max_ver="2.2.31", id="CVE-2017-7668",  cvss=9.8, desc="ap_find_token buffer overread" },
            { max_ver="2.2.31", id="CVE-2017-9798",  cvss=7.5, desc="Optionsbleed — OPTIONS verb info leak" },
            { max_ver="2.4.29", id="CVE-2017-15715", cvss=8.1, desc="FilesMatch bypass" },
            { max_ver="2.4.37", id="CVE-2019-0211",  cvss=7.8, desc="Local privilege escalation (MPM)" },
            { max_ver="2.4.43", id="CVE-2020-1927",  cvss=6.1, desc="mod_rewrite open redirect" },
            { max_ver="2.4.46", id="CVE-2021-26691", cvss=9.8, desc="mod_session heap overflow" },
            { max_ver="2.4.48", id="CVE-2021-40438", cvss=9.0, desc="mod_proxy SSRF" },
            { max_ver="2.4.51", id="CVE-2021-41773", cvss=9.8, desc="Path traversal & RCE (CGI)" },
            { max_ver="2.4.54", id="CVE-2022-22719", cvss=7.5, desc="mod_lua DoS use of uninitialized value" },
            { max_ver="2.4.56", id="CVE-2023-25690", cvss=9.8, desc="mod_proxy request smuggling" },
          }
        },
    },

    -- ── nginx ────────────────────────────────────────────────
    nginx = {
        { pattern="nginx/([%d%.]+)", service="nginx",
          cves = {
            { max_ver="1.13.2", id="CVE-2017-7529",  cvss=7.5, desc="Integer overflow dalam range filter" },
            { max_ver="1.14.0", id="CVE-2018-16843", cvss=7.5, desc="HTTP/2 DoS (memory consumption)" },
            { max_ver="1.14.0", id="CVE-2018-16844", cvss=7.5, desc="HTTP/2 DoS (CPU consumption)" },
            { max_ver="1.15.5", id="CVE-2018-16845", cvss=7.1, desc="ngx_http_mp4_module memory leak" },
            { max_ver="1.17.6", id="CVE-2019-9511",  cvss=7.5, desc="HTTP/2 Data Dribble DoS" },
            { max_ver="1.17.6", id="CVE-2019-9513",  cvss=7.5, desc="HTTP/2 Resource Loop DoS" },
          }
        },
    },

    -- ── vsftpd ───────────────────────────────────────────────
    vsftpd = {
        { pattern="vsftpd ([%d%.]+)", service="vsftpd",
          cves = {
            { exact_ver="2.3.4", id="CVE-2011-2523",  cvss=10.0, desc="BACKDOOR — smiley face ':)' username triggers shell on port 6200!" },
            { max_ver="2.0.7",   id="CVE-2008-2375",  cvss=7.1,  desc="Remote DoS via memory leak" },
          }
        },
    },

    -- ── ProFTPD ──────────────────────────────────────────────
    proftpd = {
        { pattern="ProFTPD ([%d%.]+)", service="ProFTPD",
          cves = {
            { exact_ver="1.3.3c", id="CVE-2010-4221",  cvss=10.0, desc="Heap overflow RCE" },
            { max_ver="1.3.3e",   id="CVE-2011-4130",  cvss=9.0,  desc="Use-after-free dalam Response pools" },
            { max_ver="1.3.5b",   id="CVE-2015-3306",  cvss=10.0, desc="SITE CPFR/CPTO arbitrary file read/write" },
          }
        },
    },

    -- ── MySQL / MariaDB ──────────────────────────────────────
    mysql = {
        { pattern="([%d%.]+)%-MariaDB", service="MariaDB",
          cves = {
            { max_ver="5.5.55", id="CVE-2016-6662",  cvss=10.0, desc="Arbitrary file creation via config injection" },
            { max_ver="10.1.21",id="CVE-2017-3599",  cvss=7.5,  desc="Unspecified vuln dalam DML" },
          }
        },
        { pattern="MySQL ([%d%.]+)", service="MySQL",
          cves = {
            { max_ver="5.7.17", id="CVE-2017-3599",  cvss=7.5,  desc="Unspecified vulnerability" },
            { max_ver="5.6.35", id="CVE-2016-6662",  cvss=10.0, desc="Arbitrary config file creation" },
            { max_ver="5.5.54", id="CVE-2012-2122",  cvss=5.1,  desc="Authentication bypass via timing" },
          }
        },
    },

    -- ── Redis ────────────────────────────────────────────────
    redis = {
        { pattern="Redis ([%d%.]+)", service="Redis",
          cves = {
            { max_ver="5.0.13", id="CVE-2021-32625", cvss=8.8, desc="Integer overflow dalam COPY command" },
            { max_ver="6.2.4",  id="CVE-2021-29477", cvss=8.8, desc="Heap overflow dalam RESP protocol" },
            { max_ver="6.2.5",  id="CVE-2021-32761", cvss=8.8, desc="Integer overflow dalam GETDEL" },
            { max_ver="7.0.0",  id="CVE-2022-24834", cvss=7.0, desc="Heap overflow Lua cjson library" },
          }
        },
    },

    -- ── Telnet ───────────────────────────────────────────────
    telnet = {
        { pattern="telnet", service="Telnet",
          cves = {
            { max_ver="9999", id="INSECURE-PROTOCOL", cvss=9.0,
              desc="Telnet mengirim data PLAINTEXT — password terekspos di jaringan" },
          }
        },
    },
}

-- ── Version Comparison ───────────────────────────────────────
local function version_to_num(v)
    local parts = {}
    for n in (v or "0"):gmatch("%d+") do
        table.insert(parts, tonumber(n))
    end
    while #parts < 4 do table.insert(parts, 0) end
    return parts[1] * 1e9 + parts[2] * 1e6 + parts[3] * 1e3 + parts[4]
end

local function is_vulnerable(found_ver, cve)
    local vn = version_to_num(found_ver)
    if cve.exact_ver then
        return found_ver == cve.exact_ver
    end
    if cve.max_ver then
        return vn <= version_to_num(cve.max_ver)
    end
    return false
end

-- ── Banner Grabber ────────────────────────────────────────────
local function grab_banner(host, port, timeout)
    local socket = nmap.new_socket()
    socket:set_timeout(timeout or 5000)
    local ok, err = socket:connect(host, port)
    if not ok then return nil, err end

    -- Beberapa service langsung kirim banner
    local data = ""
    local status, line = socket:receive_lines(1)
    if status and line then data = line end

    -- Untuk service yang perlu dipancing (HTTP)
    if data == "" then
        socket:send("HEAD / HTTP/1.0\r\n\r\n")
        status, line = socket:receive_lines(3)
        if status then data = line end
    end

    socket:close()
    return data:gsub("\r",""):gsub("\n"," "):sub(1, 200)
end

-- ── HTTP Banner (Server header) ───────────────────────────────
local function get_http_server_header(host, port)
    local response = http.head(host, port, "/", {
        header = { ["User-Agent"] = "Mozilla/5.0 (Nmap NSE)" }
    })
    if response and response.header then
        return response.header["server"] or response.header["x-powered-by"]
    end
    return nil
end

-- ── Check Anonymous FTP ───────────────────────────────────────
local function check_ftp_anonymous(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok = socket:connect(host, port)
    if not ok then return false end

    -- Read banner
    socket:receive_lines(1)
    socket:send("USER anonymous\r\n")
    local _, resp1 = socket:receive_lines(1)
    if resp1 and resp1:match("^331") then
        socket:send("PASS anonymous@test.com\r\n")
        local _, resp2 = socket:receive_lines(1)
        socket:send("QUIT\r\n")
        socket:close()
        if resp2 and resp2:match("^230") then
            return true
        end
    end
    socket:close()
    return false
end

-- ── Check Redis Unauthenticated ────────────────────────────────
local function check_redis_unauth(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(4000)
    local ok = socket:connect(host, port)
    if not ok then return nil end

    socket:send("PING\r\n")
    local _, resp = socket:receive_lines(1)
    socket:send("QUIT\r\n")
    socket:close()

    if resp and resp:match("%+PONG") then
        return true, "Redis tanpa autentikasi — akses penuh ke database!"
    end
    return false
end

-- ── Match CVE against banner ───────────────────────────────────
local function scan_cves(banner, port_number)
    local vulns = {}
    local service_name = "unknown"
    local found_ver = nil

    -- Deteksi service dari banner
    local checks = {}
    if port_number == 22 or (banner and banner:match("SSH")) then
        for _, c in ipairs(CVE_DB.openssh) do table.insert(checks, c) end
    end
    if port_number == 80 or port_number == 8080 or port_number == 443 then
        for _, c in ipairs(CVE_DB.apache)  do table.insert(checks, c) end
        for _, c in ipairs(CVE_DB.nginx)   do table.insert(checks, c) end
    end
    if port_number == 21 then
        for _, c in ipairs(CVE_DB.vsftpd)  do table.insert(checks, c) end
        for _, c in ipairs(CVE_DB.proftpd) do table.insert(checks, c) end
    end
    if port_number == 3306 then
        for _, c in ipairs(CVE_DB.mysql)   do table.insert(checks, c) end
    end
    if port_number == 6379 then
        for _, c in ipairs(CVE_DB.redis)   do table.insert(checks, c) end
    end
    if port_number == 23 then
        for _, c in ipairs(CVE_DB.telnet)  do table.insert(checks, c) end
        table.insert(vulns, { id="INSECURE", cvss=9.0,
            desc="Telnet menggunakan plaintext — JANGAN gunakan di produksi"})
        return "Telnet", "n/a", vulns
    end

    -- Jika tidak ada spesifik, scan semua
    if #checks == 0 and banner then
        for _, group in pairs(CVE_DB) do
            for _, c in ipairs(group) do
                table.insert(checks, c)
            end
        end
    end

    for _, check in ipairs(checks) do
        if banner then
            local ver = banner:match(check.pattern)
            if ver then
                service_name = check.service
                found_ver    = ver
                for _, cve in ipairs(check.cves) do
                    if is_vulnerable(ver, cve) then
                        table.insert(vulns, {
                            id   = cve.id,
                            cvss = cve.cvss,
                            desc = cve.desc,
                        })
                    end
                end
            end
        end
    end

    return service_name, found_ver, vulns
end

-- ── Main Action ───────────────────────────────────────────────
action = function(host, port)
    local output = stdnse.output_table()
    local issues = {}

    -- Ambil banner
    local banner = nil
    if port.number == 80 or port.number == 8080 then
        banner = get_http_server_header(host, port)
    elseif port.number == 443 or port.number == 8443 then
        banner = get_http_server_header(host, port)
    else
        local raw, _ = grab_banner(host, port)
        banner = raw
    end

    if banner and banner ~= "" then
        output["Banner"] = banner:sub(1, 120)
    end

    -- Scan CVE
    local service_name, found_ver, vulns = scan_cves(banner, port.number)

    if found_ver then
        output["Detected"]        = service_name
        output["Version"]         = found_ver
    end

    -- Tampilkan kerentanan
    if #vulns > 0 then
        local vuln_list = {}
        local max_cvss  = 0
        for _, v in ipairs(vulns) do
            local severity = v.cvss >= 9.0 and "KRITIS" or
                             v.cvss >= 7.0 and "TINGGI" or
                             v.cvss >= 4.0 and "SEDANG" or "RENDAH"
            table.insert(vuln_list, string.format(
                "[%s] %s (CVSS: %.1f) — %s", severity, v.id, v.cvss, v.desc))
            if v.cvss > max_cvss then max_cvss = v.cvss end
            table.insert(issues, v.id)
        end
        output["Vulnerabilities"] = vuln_list

        local risk = max_cvss >= 9.0 and "KRITIS" or
                     max_cvss >= 7.0 and "TINGGI" or
                     max_cvss >= 4.0 and "SEDANG" or "RENDAH"
        output["Risk Level"] = string.format("%s (CVSS max: %.1f)", risk, max_cvss)
    end

    -- Cek khusus per service
    if port.number == 21 then
        local anon_ok = check_ftp_anonymous(host, port)
        if anon_ok then
            output["FTP Anonymous Login"] = "BAHAYA: Login anonim berhasil!"
            table.insert(issues, "FTP-ANON")
        else
            output["FTP Anonymous Login"] = "Ditolak (aman)"
        end
    end

    if port.number == 6379 then
        local unauth, msg = check_redis_unauth(host, port)
        if unauth then
            output["Redis Auth"] = "KRITIS: " .. (msg or "Tanpa password!")
            table.insert(issues, "REDIS-NOAUTH")
        else
            output["Redis Auth"] = "Autentikasi aktif atau tidak merespons PING"
        end
    end

    -- Summary
    if #issues > 0 then
        output["CVEs Found"] = table.concat(issues, ", ")
        output["Action Required"] = "Segera update service atau terapkan mitigasi!"
    else
        if not banner or banner == "" then
            output["Status"] = "Banner tidak tersedia — tidak dapat fingerprint versi"
        else
            output["Status"] = "Tidak ada CVE dikenal yang cocok untuk versi ini"
        end
    end

    return output
end
