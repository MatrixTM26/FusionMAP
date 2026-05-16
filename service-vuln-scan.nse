-- ============================================================
-- service-vuln-scan.nse
-- Nmap NSE Script: Service Fingerprint & CVE Vulnerability Scanner
--
-- Usage:
--   nmap -sV --script service-vuln-scan <target>
--   nmap -p 21,22,80,443,3306,6379 --script service-vuln-scan <target>
--   nmap --script service-vuln-scan \
--        --script-args service-vuln-scan.timeout=10 <target>
--
-- Author  : MatrixTM26
-- License : Same as Nmap--See https://nmap.org/book/man-legal.html
-- ============================================================

local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local http      = require "http"

description = [[
Performs service fingerprinting and checks for known vulnerable versions.
Contains a local CVE database for common services and generates risk reports.
Supports both plain HTTP and HTTPS banner grabbing.

Supported services:
  * OpenSSH       -- CVE database for legacy versions
  * Apache httpd  -- CVE for popular versions
  * nginx         -- CVE for old versions
  * vsftpd        -- backdoor and CVE detection
  * ProFTPD       -- RCE vulnerabilities
  * MySQL/MariaDB -- privilege escalation
  * Redis         -- unauthenticated access check
  * Telnet        -- insecure protocol detection
  * FTP           -- anonymous login check
]]

author     = "MatrixTM26"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln", "discovery"}

portrule = function(host, port)
    return port.state == "open"
end

-- ── Local CVE database ────────────────────────────────────────
local CVE_DB = {
    openssh = {
        { pattern="OpenSSH[_/ ]([%d%.]+)", service="OpenSSH",
          cves={
            {max_ver="4.9",  id="CVE-2008-5161",  cvss=2.6,  desc="CBC mode information leak"},
            {max_ver="6.8",  id="CVE-2015-5600",  cvss=8.5,  desc="MaxAuthTries bypass"},
            {max_ver="7.1",  id="CVE-2016-0777",  cvss=4.0,  desc="Roaming information leak"},
            {max_ver="7.2",  id="CVE-2016-6210",  cvss=5.0,  desc="Username enumeration via timing"},
            {max_ver="7.3",  id="CVE-2016-6515",  cvss=7.8,  desc="DoS via excessively long password"},
            {max_ver="7.6",  id="CVE-2018-15473", cvss=5.3,  desc="Username enumeration (auth)"},
            {max_ver="7.7",  id="CVE-2019-6111",  cvss=5.8,  desc="SCP client path traversal"},
            {max_ver="8.5",  id="CVE-2021-28041", cvss=7.1,  desc="Double-free in ssh-agent"},
            {max_ver="9.1",  id="CVE-2023-25136", cvss=6.5,  desc="Double-free pre-auth (memory)"},
          }
        },
    },
    apache = {
        { pattern="Apache/([%d%.]+)", service="Apache httpd",
          cves={
            {max_ver="2.4.29", id="CVE-2017-15715", cvss=8.1, desc="FilesMatch bypass"},
            {max_ver="2.4.37", id="CVE-2019-0211",  cvss=7.8, desc="Local privilege escalation"},
            {max_ver="2.4.48", id="CVE-2021-40438", cvss=9.0, desc="mod_proxy SSRF"},
            {max_ver="2.4.50", id="CVE-2021-41773", cvss=9.8, desc="Path traversal and RCE (CGI)"},
            {max_ver="2.4.56", id="CVE-2023-25690", cvss=9.8, desc="mod_proxy request smuggling"},
          }
        },
    },
    nginx = {
        { pattern="nginx/([%d%.]+)", service="nginx",
          cves={
            {max_ver="1.13.2", id="CVE-2017-7529",  cvss=7.5, desc="Integer overflow in range filter"},
            {max_ver="1.14.0", id="CVE-2018-16843", cvss=7.5, desc="HTTP/2 DoS memory consumption"},
            {max_ver="1.17.6", id="CVE-2019-9511",  cvss=7.5, desc="HTTP/2 Data Dribble DoS"},
          }
        },
    },
    vsftpd = {
        { pattern="vsftpd ([%d%.]+)", service="vsftpd",
          cves={
            {exact_ver="2.3.4", id="CVE-2011-2523", cvss=10.0,
             desc="BACKDOOR -- ':)' in username opens shell on port 6200"},
            {max_ver="2.0.7",   id="CVE-2008-2375", cvss=7.1,
             desc="Remote DoS via memory leak"},
          }
        },
    },
    proftpd = {
        { pattern="ProFTPD ([%d%.]+)", service="ProFTPD",
          cves={
            {exact_ver="1.3.3c", id="CVE-2010-4221", cvss=10.0, desc="Heap overflow RCE"},
            {max_ver="1.3.5b",   id="CVE-2015-3306", cvss=10.0,
             desc="SITE CPFR/CPTO arbitrary file read/write"},
          }
        },
    },
    mysql = {
        { pattern="([%d%.]+)%-MariaDB", service="MariaDB",
          cves={
            {max_ver="5.5.55",  id="CVE-2016-6662", cvss=10.0,
             desc="Arbitrary file creation via config injection"},
          }
        },
        { pattern="MySQL ([%d%.]+)", service="MySQL",
          cves={
            {max_ver="5.6.35", id="CVE-2016-6662", cvss=10.0,
             desc="Arbitrary config file creation"},
            {max_ver="5.5.54", id="CVE-2012-2122", cvss=5.1,
             desc="Authentication bypass via timing attack"},
          }
        },
    },
    redis = {
        { pattern="Redis ([%d%.]+)", service="Redis",
          cves={
            {max_ver="6.2.4", id="CVE-2021-29477", cvss=8.8,
             desc="Heap overflow in RESP protocol parser"},
            {max_ver="7.0.0", id="CVE-2022-24834", cvss=7.0,
             desc="Heap overflow in Lua cjson library"},
          }
        },
    },
}

-- ── Version comparison ────────────────────────────────────────
local function ver2num(v)
    local p = {}
    for n in (v or "0"):gmatch("%d+") do p[#p+1] = tonumber(n) end
    while #p < 4 do p[#p+1] = 0 end
    return p[1]*1e9 + p[2]*1e6 + p[3]*1e3 + p[4]
end

local function is_vulnerable(found, cve)
    if cve.exact_ver then return found == cve.exact_ver end
    if cve.max_ver   then return ver2num(found) <= ver2num(cve.max_ver) end
    return false
end

-- ── FIX: TLS detection (same logic as http-security-audit) ────
--
-- Root cause of HTTPS TIMEOUT on port 443 / ssl failed on port 5800:
--
-- The previous code guessed TLS from a hardcoded port list.
-- Port 5800 is plain VNC-over-HTTP; sending TLS to it hangs.
-- Port 443 needs TLS but only when confirmed by Nmap or port number.
--
-- Fix: check port.version.service_tunnel first (set by -sV),
-- then fall back to canonical port numbers (443, 8443 only).
--
local function port_is_tls(port)
    if port.version then
        local t = port.version.service_tunnel
        if t == "ssl"  then return true  end
        if t == "none" then return false end
    end
    if port.service then
        if port.service:match("https") or port.service:match("ssl") then return true  end
        if port.service:match("^http$") or port.service:match("vnc") then return false end
    end
    return port.number == 443 or port.number == 8443
end

-- ── HTTP banner grab (plain or TLS) ──────────────────────────
local function grab_http_banner(host, port, timeout_ms)
    local port_copy = {
        number   = port.number,
        protocol = port.protocol,
        state    = port.state,
        service  = port_is_tls(port) and port.service or "http",
        version  = port.version,
    }
    if not port_is_tls(port) then
        port_copy.version = setmetatable(
            {service_tunnel = "none"},
            {__index = port.version or {}})
    end

    local opts = {
        timeout  = timeout_ms,
        any_af   = true,
        no_cache = true,
        header   = {["User-Agent"] = "Mozilla/5.0 (Nmap NSE MatrixTM26)"},
    }

    local response = http.head(host, port_copy, "/", opts)
    if not response or not response.status then
        response = http.get(host, port_copy, "/", opts)
    elseif response.status == 405 then
        response = http.get(host, port_copy, "/", opts)
    end

    if response and response.header then
        local srv = response.header["server"]
            or response.header["x-powered-by"]
            or response.header["x-generator"]
        return srv, response.status
    end
    return nil, nil
end

-- ── Generic TCP banner grab (non-HTTP) ───────────────────────
local function grab_tcp_banner(host, port_num, timeout_ms)
    local socket = nmap.new_socket()
    socket:set_timeout(timeout_ms)
    local ok, err = socket:connect(host, port_num)
    if not ok then return nil, err end

    socket:set_timeout(3000)
    local status, data = socket:receive_bytes(512)
    if not status or not data or data == "" then
        socket:send("HEAD / HTTP/1.0\r\n\r\n")
        socket:set_timeout(3000)
        status, data = socket:receive_bytes(512)
    end
    socket:close()
    if status and data then
        return data:gsub("[\r\n]+"," "):sub(1,256)
    end
    return nil
end

-- ── FTP anonymous login check ─────────────────────────────────
local function check_ftp_anon(host, port_num, timeout_ms)
    local socket = nmap.new_socket()
    socket:set_timeout(timeout_ms)
    if not socket:connect(host, port_num) then return false end
    socket:set_timeout(3000)
    socket:receive_lines(1)
    socket:send("USER anonymous\r\n")
    local _, r1 = socket:receive_lines(1)
    if r1 and r1:match("^331") then
        socket:send("PASS anonymous@scan\r\n")
        local _, r2 = socket:receive_lines(1)
        socket:send("QUIT\r\n")
        socket:close()
        return r2 and r2:match("^230") and true or false
    end
    socket:close()
    return false
end

-- ── Redis unauthenticated check ───────────────────────────────
local function check_redis_unauth(host, port_num, timeout_ms)
    local socket = nmap.new_socket()
    socket:set_timeout(timeout_ms)
    if not socket:connect(host, port_num) then return false end
    socket:send("PING\r\n")
    socket:set_timeout(2000)
    local _, resp = socket:receive_lines(1)
    socket:send("QUIT\r\n")
    socket:close()
    return resp and resp:match("%+PONG") and true or false
end

-- ── CVE matching ──────────────────────────────────────────────
local PORT_GROUPS = {
    [21]   = {"vsftpd","proftpd"},
    [22]   = {"openssh"},
    [80]   = {"apache","nginx"},
    [443]  = {"apache","nginx"},
    [8080] = {"apache","nginx"},
    [8443] = {"apache","nginx"},
    [3306] = {"mysql"},
    [6379] = {"redis"},
}

local function scan_cves(banner, port_num)
    if not banner then return "unknown", nil, {} end

    if port_num == 23 then
        return "Telnet", "n/a", {{
            id="INSECURE-PROTOCOL", cvss=9.0,
            desc="Telnet transmits all data in plaintext including passwords",
        }}
    end

    local checks = {}
    local groups = PORT_GROUPS[port_num]
    if groups then
        for _, g in ipairs(groups) do
            if CVE_DB[g] then
                for _, c in ipairs(CVE_DB[g]) do checks[#checks+1] = c end
            end
        end
    else
        for _, group in pairs(CVE_DB) do
            for _, c in ipairs(group) do checks[#checks+1] = c end
        end
    end

    local service_out, ver_out, vulns = "unknown", nil, {}
    for _, check in ipairs(checks) do
        local ver = banner:match(check.pattern)
        if ver then
            service_out = check.service
            ver_out     = ver
            for _, cve in ipairs(check.cves) do
                if is_vulnerable(ver, cve) then
                    vulns[#vulns+1] = {id=cve.id, cvss=cve.cvss, desc=cve.desc}
                end
            end
        end
    end
    return service_out, ver_out, vulns
end

-- ── Main action ───────────────────────────────────────────────
action = function(host, port)
    local timeout_ms = (tonumber(
        stdnse.get_script_args("service-vuln-scan.timeout")) or 8) * 1000

    local output = stdnse.output_table()
    local issues = {}
    local banner, http_status = nil, nil

    local is_http_port = (port.number == 80  or port.number == 443
                       or port.number == 8080 or port.number == 8443
                       or (port.service and port.service:match("http")))

    -- Acquire banner
    if is_http_port then
        banner, http_status = grab_http_banner(host, port, timeout_ms)
        if http_status then output["HTTP Status"] = tostring(http_status) end
        -- Fallback to raw TCP if HTTP library returned nothing
        if not banner then
            banner = grab_tcp_banner(host, port.number, timeout_ms)
        end
    else
        banner = grab_tcp_banner(host, port.number, timeout_ms)
    end

    -- Supplement with Nmap version detection if available
    if not banner and port.version and port.version.product then
        local v = port.version
        banner = (v.product or "")
            .. (v.version   and (" " .. v.version)               or "")
            .. (v.extrainfo and (" (" .. v.extrainfo .. ")")      or "")
    end

    if banner and banner ~= "" then
        output["Banner"] = banner:sub(1, 120)
    end

    local proto = port_is_tls(port) and "HTTPS (TLS)" or
                  (is_http_port and "HTTP (plaintext)" or nil)
    if proto then output["Protocol"] = proto end

    -- CVE scan
    local svc, ver, vulns = scan_cves(banner, port.number)
    if ver then
        output["Service"] = svc
        output["Version"] = ver
    end

    if #vulns > 0 then
        local list, max_cvss = {}, 0
        for _, v in ipairs(vulns) do
            local sev = v.cvss >= 9.0 and "CRITICAL"
                     or v.cvss >= 7.0 and "HIGH"
                     or v.cvss >= 4.0 and "MEDIUM" or "LOW"
            list[#list+1] = ("[%s] %s (CVSS %.1f) -- %s"):format(sev, v.id, v.cvss, v.desc)
            if v.cvss > max_cvss then max_cvss = v.cvss end
            issues[#issues+1] = v.id
        end
        output["Vulnerabilities"] = list
        local risk = max_cvss >= 9.0 and "CRITICAL"
                  or max_cvss >= 7.0 and "HIGH"
                  or max_cvss >= 4.0 and "MEDIUM" or "LOW"
        output["Risk Level"] = ("%s (max CVSS: %.1f)"):format(risk, max_cvss)
    end

    -- Service-specific checks
    if port.number == 21 then
        local anon = check_ftp_anon(host, port.number, timeout_ms)
        output["FTP Anonymous Login"] = anon
            and "DANGER: Anonymous login succeeded"
            or  "Denied (OK)"
        if anon then issues[#issues+1] = "FTP-ANON" end
    end

    if port.number == 6379 then
        local unauth = check_redis_unauth(host, port.number, timeout_ms)
        output["Redis Authentication"] = unauth
            and "CRITICAL: No authentication -- full database access possible"
            or  "Authentication required or no PONG response"
        if unauth then issues[#issues+1] = "REDIS-NOAUTH" end
    end

    if port.number == 23 then
        output["Protocol Warning"] =
            "CRITICAL: Telnet is plaintext -- replace with SSH immediately"
        issues[#issues+1] = "TELNET-PLAINTEXT"
    end

    -- Summary
    if #issues > 0 then
        output["CVEs / Issues"] = table.concat(issues, ", ")
        output["Action"]        = "Update the service or apply mitigations immediately"
    else
        output["Status"] = (not banner or banner == "")
            and "No banner received -- version fingerprinting unavailable"
            or  "No known CVEs matched for this version"
    end

    return output
end
