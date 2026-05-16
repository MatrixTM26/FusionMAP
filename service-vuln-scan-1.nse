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
--
-- NOTE: Does NOT use Nmap's http library.
--       All connections use raw nmap.new_socket() to avoid
--       ssl/timeout errors caused by library protocol guessing.
-- ============================================================

local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"

description = [[
Fingerprints service banners and matches versions against a local
CVE database.  Uses raw TCP sockets only -- no http library --
so it does not generate ssl-failed or socket-timeout errors on
plain-HTTP ports like 5800, 8080, or on HTTPS ports like 443.

Auto-detects HTTP vs HTTPS the same way http-security-audit does:
tries plain first, falls back to SSL only for 443/8443.

Services: OpenSSH, Apache, nginx, vsftpd (backdoor), ProFTPD,
MySQL/MariaDB, Redis (unauth check), Telnet, FTP (anon check).
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
        { pattern="OpenSSH[_/ ]([%d%.]+)", service="OpenSSH", cves={
            {max_ver="4.9",  id="CVE-2008-5161",  cvss=2.6,  desc="CBC mode information leak"},
            {max_ver="6.8",  id="CVE-2015-5600",  cvss=8.5,  desc="MaxAuthTries bypass"},
            {max_ver="7.1",  id="CVE-2016-0777",  cvss=4.0,  desc="Roaming information leak"},
            {max_ver="7.2",  id="CVE-2016-6210",  cvss=5.0,  desc="Username enumeration via timing"},
            {max_ver="7.3",  id="CVE-2016-6515",  cvss=7.8,  desc="DoS via excessively long password"},
            {max_ver="7.6",  id="CVE-2018-15473", cvss=5.3,  desc="Username enumeration (auth)"},
            {max_ver="7.7",  id="CVE-2019-6111",  cvss=5.8,  desc="SCP client path traversal"},
            {max_ver="8.5",  id="CVE-2021-28041", cvss=7.1,  desc="Double-free in ssh-agent"},
            {max_ver="9.1",  id="CVE-2023-25136", cvss=6.5,  desc="Double-free pre-auth"},
        }},
    },
    apache = {
        { pattern="Apache/([%d%.]+)", service="Apache httpd", cves={
            {max_ver="2.4.29", id="CVE-2017-15715", cvss=8.1, desc="FilesMatch bypass"},
            {max_ver="2.4.37", id="CVE-2019-0211",  cvss=7.8, desc="Local privilege escalation"},
            {max_ver="2.4.48", id="CVE-2021-40438", cvss=9.0, desc="mod_proxy SSRF"},
            {max_ver="2.4.50", id="CVE-2021-41773", cvss=9.8, desc="Path traversal and RCE"},
            {max_ver="2.4.56", id="CVE-2023-25690", cvss=9.8, desc="mod_proxy request smuggling"},
        }},
    },
    nginx = {
        { pattern="nginx/([%d%.]+)", service="nginx", cves={
            {max_ver="1.13.2", id="CVE-2017-7529",  cvss=7.5, desc="Integer overflow in range filter"},
            {max_ver="1.14.0", id="CVE-2018-16843", cvss=7.5, desc="HTTP/2 DoS memory consumption"},
            {max_ver="1.17.6", id="CVE-2019-9511",  cvss=7.5, desc="HTTP/2 Data Dribble DoS"},
        }},
    },
    vsftpd = {
        { pattern="vsftpd ([%d%.]+)", service="vsftpd", cves={
            {exact_ver="2.3.4", id="CVE-2011-2523", cvss=10.0,
             desc="BACKDOOR -- ':)' in username opens shell on port 6200"},
            {max_ver="2.0.7",   id="CVE-2008-2375", cvss=7.1,  desc="Remote DoS via memory leak"},
        }},
    },
    proftpd = {
        { pattern="ProFTPD ([%d%.]+)", service="ProFTPD", cves={
            {exact_ver="1.3.3c", id="CVE-2010-4221", cvss=10.0, desc="Heap overflow RCE"},
            {max_ver="1.3.5b",   id="CVE-2015-3306", cvss=10.0,
             desc="SITE CPFR/CPTO arbitrary file read/write"},
        }},
    },
    mysql = {
        { pattern="([%d%.]+)%-MariaDB", service="MariaDB", cves={
            {max_ver="5.5.55", id="CVE-2016-6662", cvss=10.0,
             desc="Arbitrary file creation via config injection"},
        }},
        { pattern="MySQL ([%d%.]+)", service="MySQL", cves={
            {max_ver="5.6.35", id="CVE-2016-6662", cvss=10.0, desc="Arbitrary config file creation"},
            {max_ver="5.5.54", id="CVE-2012-2122", cvss=5.1,  desc="Auth bypass via timing attack"},
        }},
    },
    redis = {
        { pattern="Redis ([%d%.]+)", service="Redis", cves={
            {max_ver="6.2.4", id="CVE-2021-29477", cvss=8.8, desc="Heap overflow in RESP parser"},
            {max_ver="7.0.0", id="CVE-2022-24834", cvss=7.0, desc="Heap overflow in Lua cjson"},
        }},
    },
}

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

-- ── Raw TCP banner grab (plain) ───────────────────────────────
local function tcp_banner(host, port_num, timeout_ms)
    local s = nmap.new_socket()
    s:set_timeout(timeout_ms)
    local ok, err = s:connect(host, port_num)
    if not ok then return nil, err end

    -- Some services send banner immediately; others need a probe
    s:set_timeout(3000)
    local ok2, data = s:receive_bytes(512)
    if not ok2 or not data or data == "" then
        -- Send a minimal HTTP probe to wake up HTTP servers
        s:send("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
        s:set_timeout(3000)
        ok2, data = s:receive_bytes(512)
    end
    s:close()
    if ok2 and data and data ~= "" then
        return data:gsub("[\r\n]+"," "):sub(1,256)
    end
    return nil, "no data"
end

-- ── HTTP banner grab: plain with SSL fallback for 443/8443 ────
--
-- Root cause of all previous ssl-failed / http.socket errors:
-- The http library decides whether to use SSL based on port.service,
-- which may be wrong when scanning without -sV.  We bypass it
-- entirely and manage the socket ourselves.
--
local function http_banner(host, port_num, timeout_ms)
    local host_str = type(host)=="table" and (host.targetname or host.ip) or tostring(host)
    local req = "HEAD / HTTP/1.1\r\nHost: " .. host_str
             .. "\r\nUser-Agent: Mozilla/5.0 (Nmap NSE MatrixTM26)"
             .. "\r\nConnection: close\r\n\r\n"

    -- Inner function: attempt request with or without SSL
    local function attempt(use_ssl)
        local s = nmap.new_socket()
        s:set_timeout(timeout_ms)
        if use_ssl then s:set_option("ssl", true) end
        local ok, err = s:connect(host, port_num)
        if not ok then s:close(); return nil, err end
        local sent, serr = s:send(req)
        if not sent then s:close(); return nil, serr end
        local buf = ""
        s:set_timeout(5000)
        while #buf < 4096 do
            local ok2, chunk = s:receive_bytes(1024)
            if not ok2 then break end
            buf = buf .. chunk
            if buf:match("\r\n\r\n") then break end
        end
        s:close()
        -- Validate it's actually HTTP
        if buf:match("^HTTP/") then return buf, nil end
        return nil, "not HTTP"
    end

    -- Try plain first (safe for ALL ports including 5800, 8080)
    local buf, err = attempt(false)
    if buf then
        -- Extract Server header
        local srv = buf:match("[Ss]erver:%s*([^\r\n]+)")
        local status = tonumber(buf:match("^HTTP/%S+ (%d+)"))
        return srv, status, false
    end

    -- Only fall back to SSL for canonical TLS ports
    if port_num == 443 or port_num == 8443 then
        buf, err = attempt(true)
        if buf then
            local srv = buf:match("[Ss]erver:%s*([^\r\n]+)")
            local status = tonumber(buf:match("^HTTP/%S+ (%d+)"))
            return srv, status, true
        end
    end

    return nil, nil, false
end

-- ── FTP anonymous check ───────────────────────────────────────
local function ftp_anon(host, port_num, timeout_ms)
    local s = nmap.new_socket()
    s:set_timeout(timeout_ms)
    if not s:connect(host, port_num) then return false end
    s:set_timeout(3000)
    s:receive_lines(1)
    s:send("USER anonymous\r\n")
    local _, r1 = s:receive_lines(1)
    if r1 and r1:match("^331") then
        s:send("PASS anonymous@scan\r\n")
        local _, r2 = s:receive_lines(1)
        s:send("QUIT\r\n"); s:close()
        return r2 and r2:match("^230") and true or false
    end
    s:close(); return false
end

-- ── Redis unauthenticated check ───────────────────────────────
local function redis_unauth(host, port_num, timeout_ms)
    local s = nmap.new_socket()
    s:set_timeout(timeout_ms)
    if not s:connect(host, port_num) then return false end
    s:send("PING\r\n")
    s:set_timeout(2000)
    local _, r = s:receive_lines(1)
    s:send("QUIT\r\n"); s:close()
    return r and r:match("%+PONG") and true or false
end

-- ── CVE matching ──────────────────────────────────────────────
local function scan_cves(banner, port_num)
    if not banner then return "unknown", nil, {} end
    if port_num == 23 then
        return "Telnet","n/a",{{id="INSECURE-PROTOCOL",cvss=9.0,
            desc="Telnet is plaintext -- all data including passwords exposed"}}
    end
    local checks = {}
    local groups = PORT_GROUPS[port_num]
    if groups then
        for _, g in ipairs(groups) do
            if CVE_DB[g] then for _, c in ipairs(CVE_DB[g]) do checks[#checks+1]=c end end
        end
    else
        for _, grp in pairs(CVE_DB) do for _, c in ipairs(grp) do checks[#checks+1]=c end end
    end
    local svc, ver, vulns = "unknown", nil, {}
    for _, check in ipairs(checks) do
        local v = banner:match(check.pattern)
        if v then
            svc = check.service; ver = v
            for _, cve in ipairs(check.cves) do
                if is_vulnerable(v, cve) then
                    vulns[#vulns+1] = {id=cve.id, cvss=cve.cvss, desc=cve.desc}
                end
            end
        end
    end
    return svc, ver, vulns
end

-- ── Main action ───────────────────────────────────────────────
action = function(host, port)
    local timeout_ms = (tonumber(
        stdnse.get_script_args("service-vuln-scan.timeout")) or 8) * 1000

    local output = stdnse.output_table()
    local issues = {}
    local banner = nil

    local is_http = (port.number==80 or port.number==443
                  or port.number==8080 or port.number==8443
                  or (port.service and port.service:match("http")))

    if is_http then
        local srv, status, tls = http_banner(host, port.number, timeout_ms)
        if status then output["HTTP Status"] = tostring(status) end
        if tls ~= nil then
            output["Protocol"] = tls and "HTTPS (TLS)" or "HTTP (plaintext)"
        end
        banner = srv
        -- Fallback: raw TCP if HTTP returned nothing
        if not banner then
            banner = tcp_banner(host, port.number, timeout_ms)
        end
    else
        banner = tcp_banner(host, port.number, timeout_ms)
    end

    -- Supplement with Nmap -sV data if banner still empty
    if not banner and port.version and port.version.product then
        local v = port.version
        banner = (v.product or "")
            .. (v.version   and (" " .. v.version)          or "")
            .. (v.extrainfo and (" (" .. v.extrainfo .. ")") or "")
    end

    if banner and banner ~= "" then
        output["Banner"] = banner:sub(1,120)
    end

    -- CVE scan
    local svc, ver, vulns = scan_cves(banner, port.number)
    if ver then output["Service"] = svc; output["Version"] = ver end

    if #vulns > 0 then
        local list, max_cvss = {}, 0
        for _, v in ipairs(vulns) do
            local sev = v.cvss>=9.0 and "CRITICAL" or v.cvss>=7.0 and "HIGH"
                     or v.cvss>=4.0 and "MEDIUM" or "LOW"
            list[#list+1] = ("[%s] %s (CVSS %.1f) -- %s"):format(sev,v.id,v.cvss,v.desc)
            if v.cvss > max_cvss then max_cvss = v.cvss end
            issues[#issues+1] = v.id
        end
        output["Vulnerabilities"] = list
        local risk = max_cvss>=9.0 and "CRITICAL" or max_cvss>=7.0 and "HIGH"
                  or max_cvss>=4.0 and "MEDIUM" or "LOW"
        output["Risk Level"] = ("%s (max CVSS: %.1f)"):format(risk, max_cvss)
    end

    -- Service-specific checks
    if port.number == 21 then
        local anon = ftp_anon(host, port.number, timeout_ms)
        output["FTP Anonymous Login"] = anon
            and "DANGER: Anonymous login succeeded" or "Denied (OK)"
        if anon then issues[#issues+1] = "FTP-ANON" end
    end

    if port.number == 6379 then
        local unauth = redis_unauth(host, port.number, timeout_ms)
        output["Redis Authentication"] = unauth
            and "CRITICAL: No authentication -- full database access possible"
            or  "Authentication required or no PONG response"
        if unauth then issues[#issues+1] = "REDIS-NOAUTH" end
    end

    if port.number == 23 then
        output["Protocol Warning"] =
            "CRITICAL: Telnet is plaintext -- replace with SSH"
        issues[#issues+1] = "TELNET-PLAINTEXT"
    end

    if #issues > 0 then
        output["CVEs / Issues"] = table.concat(issues, ", ")
        output["Action"] = "Update the service or apply mitigations immediately"
    else
        output["Status"] = (not banner or banner=="")
            and "No banner received -- version fingerprinting unavailable"
            or  "No known CVEs matched for this version"
    end

    return output
end
