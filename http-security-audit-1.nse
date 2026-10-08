-- ============================================================
-- http-security-audit.nse
-- Nmap NSE Script: HTTP/HTTPS Security Header Audit
--
-- Usage:
--   nmap -p 80,443,5800,8080,8443 --script http-security-audit <target>
--   nmap -p 443 --script http-security-audit \
--        --script-args http-security-audit.path=/login,http-security-audit.timeout=10 <target>
--
-- Author  : MatrixTM26
-- License : Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- NOTE: This script does NOT use Nmap's http library.
--       It uses raw nmap.new_socket() to avoid ssl/timeout bugs
--       that occur when the http library guesses the wrong protocol.
--       SSL is probed automatically: try plain first, if connection
--       is reset or data looks like a TLS alert, retry with SSL.
-- ============================================================

local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"

description = [[
Audits HTTP/HTTPS response headers for missing or misconfigured
security controls.  Uses raw TCP sockets (no http library) so it
works reliably on all ports without SSL/timeout errors.

Auto-detects TLS: tries plain HTTP first; if the server responds
with a TLS alert or closes immediately, retries with SSL.

Checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, X-XSS-Protection, CORP,
COOP, Cache-Control, Clear-Site-Data, CORS, cookie flags,
clickjacking, server information disclosure.
Score: 0-100 with letter grade A-F.
]]

author     = "MatrixTM26"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

-- ── Security headers ──────────────────────────────────────────
local SECURITY_HEADERS = {
    { name="Strict-Transport-Security",    w=15, desc="HSTS -- prevents HTTP downgrade" },
    { name="Content-Security-Policy",      w=20, desc="CSP -- prevents XSS and injection" },
    { name="X-Frame-Options",              w=10, desc="Clickjacking protection" },
    { name="X-Content-Type-Options",       w=10, desc="MIME sniffing protection" },
    { name="Referrer-Policy",              w=8,  desc="Controls URL leakage" },
    { name="Permissions-Policy",           w=8,  desc="Browser feature policy" },
    { name="X-XSS-Protection",             w=5,  desc="Legacy browser XSS filter" },
    { name="Cross-Origin-Opener-Policy",   w=7,  desc="Cross-origin isolation" },
    { name="Cross-Origin-Resource-Policy", w=7,  desc="Cross-origin resource sharing" },
    { name="Cache-Control",                w=5,  desc="Caching directive" },
    { name="Clear-Site-Data",              w=5,  desc="Data clearing on logout" },
}

local LEAK_HEADERS = {
    "Server","X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version",
    "X-Generator","X-Drupal-Cache","X-Varnish","Via",
    "X-CF-Powered-By","X-Runtime","X-Version","X-Backend-Server",
}

-- ── HTTP request builder ──────────────────────────────────────
local function build_request(host_str, path)
    return table.concat({
        "HEAD " .. path .. " HTTP/1.1",
        "Host: " .. host_str,
        "User-Agent: Mozilla/5.0 (Nmap NSE MatrixTM26)",
        "Accept: */*",
        "Accept-Encoding: identity",
        "Connection: close",
        "", "",
    }, "\r\n")
end

-- ── Raw HTTP response parser ──────────────────────────────────
local function parse_response(raw)
    if not raw or raw == "" then return nil end

    local headers = {}
    local status_line = raw:match("^(HTTP/[^\r\n]+)")
    local status_code = status_line and tonumber(status_line:match(" (%d%d%d) "))

    -- Parse headers (case-insensitive store, lowercased keys)
    for k, v in raw:gmatch("\r\n([^:\r\n]+):%s*([^\r\n]+)") do
        headers[k:lower()] = v
    end

    -- set-cookie can appear multiple times; collect as table
    local cookies = {}
    for c in raw:gmatch("\r\nSet%-Cookie:%s*([^\r\n]+)") do
        cookies[#cookies+1] = c
    end
    if #cookies > 0 then headers["set-cookie"] = cookies end

    return { status=status_code, status_line=status_line, header=headers }
end

-- ── Core socket request (plain or SSL) ───────────────────────
local function raw_request(host, port_num, path, use_ssl, timeout_ms)
    local socket = nmap.new_socket()
    socket:set_timeout(timeout_ms)

    if use_ssl then
        -- set_option must be called before connect
        socket:set_option("ssl", true)
    end

    local ok, err = socket:connect(host, port_num)
    if not ok then
        socket:close()
        return nil, ("connect failed: %s"):format(err or "unknown")
    end

    local host_str = type(host) == "table" and (host.targetname or host.ip) or tostring(host)
    local req = build_request(host_str, path)

    local sent, serr = socket:send(req)
    if not sent then
        socket:close()
        return nil, ("send failed: %s"):format(serr or "unknown")
    end

    -- Collect full response headers (until blank line or timeout)
    local buf   = ""
    local limit = 8192
    socket:set_timeout(timeout_ms)

    while #buf < limit do
        local s, data = socket:receive_bytes(1024)
        if not s then break end
        buf = buf .. data
        -- Stop once we have the header section
        if buf:match("\r\n\r\n") or buf:match("\n\n") then break end
    end
    socket:close()

    if buf == "" then
        return nil, "no data received"
    end

    -- HEAD on a non-HTTP port may return binary garbage -- detect and reject
    if not buf:match("^HTTP/") then
        return nil, "not an HTTP response"
    end

    return parse_response(buf), nil
end

-- ── Auto-detect TLS and fetch response ───────────────────────
--
-- Strategy (eliminates ssl-failed and http.socket errors):
--
--   1. Check Nmap's port metadata first (most reliable when -sV used).
--   2. If metadata says "ssl" -> go straight to SSL.
--   3. If metadata says "none" or port is not 443/8443 -> try plain HTTP.
--   4. Plain attempt: if we get a valid HTTP response, done.
--   5. If plain fails and port is 443/8443 or metadata hints SSL,
--      retry once with SSL.
--   6. Never attempt SSL on ports that returned a valid plain-HTTP
--      response -- avoids the 5800/VNC false-SSL problem.
--
local function fetch(host, port, path, timeout_ms)
    -- Step 1: read Nmap metadata
    local meta_ssl = false
    local meta_plain = false
    if port.version then
        local t = port.version.service_tunnel
        if t == "ssl"  then meta_ssl   = true end
        if t == "none" then meta_plain = true end
    end
    if port.service then
        if port.service:match("https") or port.service:match("ssl") then
            meta_ssl = true
        end
        if port.service:match("^http$") or port.service:match("vnc")
        or port.service:match("vnc%-http") then
            meta_plain = true
        end
    end

    local port_num = port.number

    -- Step 2: metadata says SSL -> only try SSL, no plain fallback
    if meta_ssl and not meta_plain then
        local resp, err = raw_request(host, port_num, path, true, timeout_ms)
        return resp, err, true
    end

    -- Step 3: try plain HTTP first (safe for ALL ports)
    if not meta_ssl then
        local resp, err = raw_request(host, port_num, path, false, timeout_ms)
        if resp then return resp, nil, false end
        -- If plain failed with "not an HTTP response" it might be TLS
        -- Only retry with SSL for known-TLS port numbers
        if port_num ~= 443 and port_num ~= 8443 then
            return nil, err, false
        end
    end

    -- Step 4: SSL retry for 443/8443 (or meta_ssl with meta_plain conflict)
    local resp, err = raw_request(host, port_num, path, true, timeout_ms)
    return resp, err, (resp ~= nil)
end

-- ── Header helpers ────────────────────────────────────────────
local function hget(headers, name)
    return headers[name:lower()]
end

local function check_hsts(v)
    local out = {}
    local age = tonumber(v:match("max%-age=(%d+)"))
    if not age then
        out[#out+1] = "max-age missing"
    elseif age < 31536000 then
        out[#out+1] = ("max-age too short (%d < 31536000)"):format(age)
    end
    if not v:match("includeSubDomains") then out[#out+1] = "includeSubDomains absent" end
    return out
end

local function check_csp(v)
    local out = {}
    if v:match("'unsafe%-inline'") then out[#out+1] = "DANGER: unsafe-inline allows XSS" end
    if v:match("'unsafe%-eval'")   then out[#out+1] = "DANGER: unsafe-eval allows dynamic code" end
    if v:match("%*")               then out[#out+1] = "WARNING: wildcard * is overly permissive" end
    if not v:match("default%-src") and not v:match("script%-src") then
        out[#out+1] = "No default-src or script-src directive"
    end
    return out
end

local function check_cookies(headers)
    local out   = {}
    local clist = headers["set-cookie"]
    if not clist then return out end
    if type(clist) ~= "table" then clist = {clist} end
    for _, c in ipairs(clist) do
        local name  = c:match("^([^=;]+)")
        local lower = c:lower()
        local iss   = {}
        if not lower:match("secure")   then iss[#iss+1] = "missing Secure"   end
        if not lower:match("httponly") then iss[#iss+1] = "missing HttpOnly"  end
        if not lower:match("samesite") then iss[#iss+1] = "missing SameSite"  end
        if #iss > 0 and name then
            out[#out+1] = ("Cookie '%s': %s"):format(name:gsub("%s",""), table.concat(iss,", "))
        end
    end
    return out
end

-- ── Main action ───────────────────────────────────────────────
action = function(host, port)
    local path       = stdnse.get_script_args("http-security-audit.path")    or "/"
    local timeout_ms = (tonumber(
        stdnse.get_script_args("http-security-audit.timeout")) or 10) * 1000

    local response, err, used_ssl = fetch(host, port, path, timeout_ms)

    if not response then
        return stdnse.format_output(false,
            ("Could not retrieve headers: %s"):format(err or "unknown error"))
    end

    -- If HEAD returned 405, try GET (some servers reject HEAD)
    if response.status == 405 or response.status == 501 then
        local req = build_request(
            type(host)=="table" and (host.targetname or host.ip) or tostring(host), path)
        req = req:gsub("^HEAD", "GET")
        local sock2 = nmap.new_socket()
        sock2:set_timeout(timeout_ms)
        if used_ssl then sock2:set_option("ssl", true) end
        if sock2:connect(host, port.number) then
            sock2:send(req)
            local buf2 = ""
            while #buf2 < 8192 do
                local s, d = sock2:receive_bytes(1024)
                if not s then break end
                buf2 = buf2 .. d
                if buf2:match("\r\n\r\n") then break end
            end
            sock2:close()
            if buf2:match("^HTTP/") then
                local r2 = parse_response(buf2)
                if r2 then response = r2 end
            end
        end
    end

    local output    = stdnse.output_table()
    local score     = 0
    local max_score = 0
    local present   = {}
    local missing   = {}
    local warnings  = {}

    output["Protocol"]    = used_ssl and "HTTPS (TLS)" or "HTTP (plaintext)"
    output["HTTP Status"] = tostring(response.status or "unknown")

    -- 1. Security header audit
    for _, h in ipairs(SECURITY_HEADERS) do
        max_score = max_score + h.w
        local val = hget(response.header, h.name)
        if val then
            score = score + h.w
            present[#present+1] = ("[PRESENT] %-42s %s"):format(h.name, val:sub(1,70))
            local deep = {}
            if     h.name == "Strict-Transport-Security"   then deep = check_hsts(val)
            elseif h.name == "Content-Security-Policy"     then deep = check_csp(val)
            elseif h.name == "X-Frame-Options" then
                if val:upper() ~= "DENY" and val:upper() ~= "SAMEORIGIN" then
                    deep[#deep+1] = ("unexpected value '%s'"):format(val)
                end
            elseif h.name == "X-Content-Type-Options" then
                if val:lower() ~= "nosniff" then
                    deep[#deep+1] = ("should be 'nosniff', got: %s"):format(val)
                end
            end
            for _, d in ipairs(deep) do
                warnings[#warnings+1] = "  [!] " .. h.name .. " -- " .. d
            end
        else
            missing[#missing+1] = ("[MISSING] %-42s %s"):format(h.name, h.desc)
        end
    end

    -- 2. Information disclosure
    local leaks = {}
    for _, lh in ipairs(LEAK_HEADERS) do
        local val = hget(response.header, lh)
        if val then leaks[#leaks+1] = lh .. ": " .. val end
    end

    -- 3. CORS
    local acao = hget(response.header, "Access-Control-Allow-Origin")
    if acao == "*" then
        warnings[#warnings+1] = "DANGER: Access-Control-Allow-Origin: * allows all origins"
    end

    -- 4. Cookie audit
    for _, c in ipairs(check_cookies(response.header)) do
        warnings[#warnings+1] = "Cookie: " .. c
    end

    -- 5. Clickjacking
    local xfo = hget(response.header, "X-Frame-Options")
    local csp = hget(response.header, "Content-Security-Policy")
    if not xfo and not (csp and csp:match("frame%-ancestors")) then
        warnings[#warnings+1] =
            "DANGER: No clickjacking protection (X-Frame-Options or CSP frame-ancestors)"
    end

    -- 6. HSTS on plain HTTP
    if not used_ssl and hget(response.header, "Strict-Transport-Security") then
        warnings[#warnings+1] =
            "MISCONFIGURATION: HSTS sent over plain HTTP -- browsers ignore it"
    end
    if not used_ssl then
        warnings[#warnings+1] = "INFO: Site is plain HTTP -- consider enforcing HTTPS"
    end

    -- Score and grade
    local pct   = math.floor(score / max_score * 100)
    local grade = pct>=90 and "A" or pct>=75 and "B" or pct>=60 and "C"
               or pct>=40 and "D" or "F"
    output["Security Score"] = ("%d/100 -- Grade: %s"):format(pct, grade)

    if #present  > 0 then output["Headers Present"] = present  end
    if #missing  > 0 then output["Headers Missing"]  = missing  end
    if #warnings > 0 then output["Warnings"]         = warnings end
    if #leaks    > 0 then output["Info Disclosure"]  = leaks    end

    -- Recommendations
    local reco = {}
    if not hget(response.header, "Content-Security-Policy") then
        reco[#reco+1] = "Add Content-Security-Policy (highest priority)"
    end
    if not used_ssl then
        reco[#reco+1] = "Enable HTTPS and redirect all HTTP traffic"
    elseif not hget(response.header, "Strict-Transport-Security") then
        reco[#reco+1] = "Enable HSTS: max-age=31536000; includeSubDomains"
    end
    if not xfo then
        reco[#reco+1] = "Add X-Frame-Options: DENY"
    end
    if #leaks > 0 then
        reco[#reco+1] = "Remove server/technology headers to reduce fingerprinting"
    end
    if #reco > 0 then output["Recommendations"] = reco end
    return output
end
