-- ============================================================
-- http-security-audit.nse
-- Nmap NSE Script: HTTP/HTTPS Security Header & Misconfiguration Audit
--
-- Usage:
--   nmap -p 80,443 --script http-security-audit <target>
--   nmap -p 5800   --script http-security-audit <target>
--   nmap -p 443    --script http-security-audit \
--        --script-args http-security-audit.path=/login,http-security-audit.timeout=10 <target>
--
-- Author  : MatrixTM26
-- License : Same as Nmap--See https://nmap.org/book/man-legal.html
-- ============================================================

local http      = require "http"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local nmap      = require "nmap"

description = [[
Performs a security audit on HTTP/HTTPS response headers.
Works on both plain HTTP and HTTPS (TLS) ports, including
non-standard ports such as 5800, 8080, 8443, etc.

Checks performed:
  * 11 security headers (HSTS, CSP, X-Frame-Options, etc.)
  * Server / technology fingerprint from response headers
  * Cookies missing Secure / HttpOnly / SameSite flags
  * CORS wildcard misconfiguration
  * Clickjacking vulnerability
  * HSTS misconfiguration on plain HTTP
  * Security score 0-100 with letter grade
]]

author     = "MatrixTM26"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

-- ── Security headers to audit ─────────────────────────────────
local SECURITY_HEADERS = {
    { name="Strict-Transport-Security",    weight=15, desc="HSTS -- prevents HTTP downgrade" },
    { name="Content-Security-Policy",      weight=20, desc="CSP -- prevents XSS and injection" },
    { name="X-Frame-Options",              weight=10, desc="Clickjacking protection" },
    { name="X-Content-Type-Options",       weight=10, desc="MIME sniffing protection" },
    { name="Referrer-Policy",              weight=8,  desc="Controls URL leakage" },
    { name="Permissions-Policy",           weight=8,  desc="Browser feature policy" },
    { name="X-XSS-Protection",             weight=5,  desc="Legacy browser XSS filter" },
    { name="Cross-Origin-Opener-Policy",   weight=7,  desc="Cross-origin isolation" },
    { name="Cross-Origin-Resource-Policy", weight=7,  desc="Cross-origin resource sharing" },
    { name="Cache-Control",                weight=5,  desc="Caching directive" },
    { name="Clear-Site-Data",              weight=5,  desc="Data clearing on logout" },
}

local LEAK_HEADERS = {
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
    "X-CF-Powered-By", "X-Runtime", "X-Version", "X-Backend-Server",
}

-- ── Helpers ───────────────────────────────────────────────────
local function header_get(response, name)
    local lower = name:lower()
    for k, v in pairs(response.header) do
        if k:lower() == lower then return v end
    end
    return nil
end

local function check_hsts(value)
    local issues = {}
    local age = tonumber(value:match("max%-age=(%d+)"))
    if not age then
        issues[#issues+1] = "max-age missing"
    elseif age < 31536000 then
        issues[#issues+1] = ("max-age too short (%d < 31536000)"):format(age)
    end
    if not value:match("includeSubDomains") then
        issues[#issues+1] = "includeSubDomains absent"
    end
    return issues
end

local function check_csp(value)
    local issues = {}
    if value:match("'unsafe%-inline'") then
        issues[#issues+1] = "DANGER: 'unsafe-inline' allows XSS"
    end
    if value:match("'unsafe%-eval'") then
        issues[#issues+1] = "DANGER: 'unsafe-eval' allows dynamic code execution"
    end
    if value:match("%*") then
        issues[#issues+1] = "WARNING: wildcard '*' is overly permissive"
    end
    if not value:match("default%-src") and not value:match("script%-src") then
        issues[#issues+1] = "No default-src or script-src directive found"
    end
    return issues
end

local function analyze_cookies(response)
    local results = {}
    local cookies = response.header["set-cookie"]
    if not cookies then return results end
    local list = type(cookies) == "table" and cookies or {cookies}
    for _, cookie in ipairs(list) do
        local name  = cookie:match("^([^=;]+)")
        local lower = cookie:lower()
        local issues = {}
        if not lower:match("secure")   then issues[#issues+1] = "missing Secure flag"              end
        if not lower:match("httponly") then issues[#issues+1] = "missing HttpOnly flag"             end
        if not lower:match("samesite") then issues[#issues+1] = "missing SameSite flag (CSRF risk)" end
        if #issues > 0 and name then
            results[#results+1] = ("Cookie '%s': %s"):format(
                name:gsub("%s",""), table.concat(issues, ", "))
        end
    end
    return results
end

-- ── FIX: SSL detection for non-standard ports ─────────────────
--
-- Root cause of "ssl failed: TIMEOUT" on port 5800:
--
-- The previous code used a static list (443, 8443) to decide
-- whether to use TLS.  Port 5800 is VNC-over-HTTP -- plain HTTP,
-- NOT TLS.  Sending a TLS ClientHello to it causes a timeout.
--
-- Fix strategy:
--   1. Consult Nmap's port.version.service_tunnel field first.
--      Nmap sets this to "ssl" when -sV has already confirmed TLS.
--   2. Fall back to a port-number heuristic ONLY for the canonical
--      TLS ports (443, 8443).  All other ports default to plain HTTP
--      unless Nmap's version detection says otherwise.
--   3. If http.head() returns nil (socket error / timeout), do NOT
--      retry with SSL -- return a clean error message instead.
--
local function is_tls_port(port)
    -- Nmap version detection result (most reliable)
    if port.version then
        local tunnel = port.version.service_tunnel
        if tunnel == "ssl" then return true  end
        if tunnel == "none" then return false end
    end
    -- Service name heuristic
    if port.service then
        if port.service:match("https") or port.service:match("ssl") then
            return true
        end
        if port.service:match("^http$") or port.service:match("vnc") then
            return false
        end
    end
    -- Port-number heuristic -- only canonical TLS ports
    return (port.number == 443 or port.number == 8443)
end

local function do_request(host, port, path, timeout_ms)
    local opts = {
        timeout  = timeout_ms,
        any_af   = true,
        no_cache = true,
        header   = {
            ["User-Agent"]      = "Mozilla/5.0 (Nmap NSE MatrixTM26)",
            ["Accept"]          = "*/*",
            ["Accept-Encoding"] = "identity",
            ["Connection"]      = "close",
        },
    }

    -- http library uses port.service to decide HTTP vs HTTPS.
    -- Force it to plain HTTP for non-TLS ports by temporarily
    -- overriding the service field on a shallow copy.
    local port_copy = {
        number  = port.number,
        protocol= port.protocol,
        state   = port.state,
        service = port.service,
        version = port.version,
    }
    if not is_tls_port(port) then
        -- Ensure the library does not attempt TLS
        port_copy.service = "http"
        port_copy.version = port_copy.version or {}
        port_copy.version = setmetatable({service_tunnel="none"}, {__index = port_copy.version or {}})
    end

    local response = http.head(host, port_copy, path, opts)

    -- HEAD not supported -> retry with GET
    if not response or not response.status then
        response = http.get(host, port_copy, path, opts)
    elseif response.status == 405 or response.status == 501 then
        response = http.get(host, port_copy, path, opts)
    end

    return response
end

-- ── Main action ───────────────────────────────────────────────
action = function(host, port)
    local path       = stdnse.get_script_args("http-security-audit.path")    or "/"
    local timeout_ms = (tonumber(
        stdnse.get_script_args("http-security-audit.timeout")) or 10) * 1000

    local response = do_request(host, port, path, timeout_ms)

    if not response or not response.status then
        return stdnse.format_output(false, "Could not connect to target")
    end

    local output    = stdnse.output_table()
    local score     = 0
    local max_score = 0
    local present   = {}
    local missing   = {}
    local warnings  = {}

    local tls = is_tls_port(port)
    output["Protocol"]    = tls and "HTTPS (TLS)" or "HTTP (plaintext)"
    output["HTTP Status"] = tostring(response.status)

    -- 1. Security header audit
    for _, h in ipairs(SECURITY_HEADERS) do
        max_score = max_score + h.weight
        local val = header_get(response, h.name)
        if val then
            score = score + h.weight
            present[#present+1] = ("[PRESENT] %-42s %s"):format(h.name, val:sub(1,70))
            local deep = {}
            if     h.name == "Strict-Transport-Security"   then deep = check_hsts(val)
            elseif h.name == "Content-Security-Policy"     then deep = check_csp(val)
            elseif h.name == "X-Frame-Options" then
                if val:upper() ~= "DENY" and val:upper() ~= "SAMEORIGIN" then
                    deep[#deep+1] = ("Unusual value '%s' (expected DENY or SAMEORIGIN)"):format(val)
                end
            elseif h.name == "X-Content-Type-Options" then
                if val:lower() ~= "nosniff" then
                    deep[#deep+1] = ("Value should be 'nosniff', got: %s"):format(val)
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
        local val = header_get(response, lh)
        if val then leaks[#leaks+1] = lh .. ": " .. val end
    end

    -- 3. CORS
    local acao = header_get(response, "Access-Control-Allow-Origin")
    if acao == "*" then
        warnings[#warnings+1] = "DANGER: Access-Control-Allow-Origin: * allows all origins"
    end

    -- 4. Cookie audit
    for _, ci in ipairs(analyze_cookies(response)) do
        warnings[#warnings+1] = "Cookie: " .. ci
    end

    -- 5. Clickjacking
    local xfo = header_get(response, "X-Frame-Options")
    local csp = header_get(response, "Content-Security-Policy")
    if not xfo and not (csp and csp:match("frame%-ancestors")) then
        warnings[#warnings+1] =
            "DANGER: No clickjacking protection (X-Frame-Options or CSP frame-ancestors missing)"
    end

    -- 6. HSTS on plain HTTP
    if not tls and header_get(response, "Strict-Transport-Security") then
        warnings[#warnings+1] =
            "MISCONFIGURATION: HSTS sent over plain HTTP -- browsers ignore it"
    end
    if not tls then
        warnings[#warnings+1] = "INFO: Site is plain HTTP -- consider enforcing HTTPS"
    end

    -- Score and grade
    local pct   = math.floor(score / max_score * 100)
    local grade = pct >= 90 and "A" or pct >= 75 and "B"
               or pct >= 60 and "C" or pct >= 40 and "D" or "F"

    output["Security Score"] = ("%d/100 -- Grade: %s"):format(pct, grade)

    if #present  > 0 then output["Headers Present"] = present  end
    if #missing  > 0 then output["Headers Missing"]  = missing  end
    if #warnings > 0 then output["Warnings"]         = warnings end
    if #leaks    > 0 then output["Info Disclosure"]  = leaks    end

    -- Recommendations
    local reco = {}
    if not header_get(response, "Content-Security-Policy") then
        reco[#reco+1] = "Add Content-Security-Policy to prevent XSS (highest priority)"
    end
    if not tls then
        reco[#reco+1] = "Enable HTTPS and redirect all HTTP traffic to HTTPS"
    elseif not header_get(response, "Strict-Transport-Security") then
        reco[#reco+1] = "Enable HSTS: max-age=31536000; includeSubDomains; preload"
    end
    if not xfo then
        reco[#reco+1] = "Add X-Frame-Options: DENY to prevent clickjacking"
    end
    if #leaks > 0 then
        reco[#reco+1] = "Remove server/technology headers to reduce fingerprinting surface"
    end
    if #reco > 0 then output["Recommendations"] = reco end

    return output
end
