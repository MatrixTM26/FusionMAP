-- ============================================================
-- http-security-audit.nse
-- Nmap NSE Script: HTTP Security Header & Misconfiguration Audit
--
-- Penggunaan:
--   nmap -p 80,443 --script http-security-audit <target>
--   nmap -p 80,443 --script http-security-audit --script-args http-security-audit.path=/login <target>
--
-- Author : LuaNetSec Project
-- License: Same as Nmap (https://nmap.org/book/man-legal.html)
-- ============================================================

local http      = require "http"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

-- ── NSE Metadata ────────────────────────────────────────────
description = [[
Melakukan audit keamanan pada HTTP response headers.
Script ini memeriksa keberadaan dan konfigurasi security headers kritis,
mendeteksi informasi yang bocor (server versi, teknologi), serta
memberikan skor keamanan 0-100.

Informasi yang dikumpulkan:
  * Security headers (HSTS, CSP, X-Frame-Options, dll.)
  * Server/technology fingerprint dari header
  * Cookies tanpa flag Secure/HttpOnly
  * CORS misconfiguration
  * Clickjacking vulnerability
]]

author      = "LuaNetSec"
license     = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories  = {"safe", "discovery", "vuln"}

-- ── Port Rule: jalankan pada port HTTP/HTTPS ─────────────────
portrule = shortport.http

-- ── Konstanta ────────────────────────────────────────────────
local SECURITY_HEADERS = {
    { name = "Strict-Transport-Security",  weight = 15, desc = "HSTS - Mencegah downgrade ke HTTP" },
    { name = "Content-Security-Policy",    weight = 20, desc = "CSP - Mencegah XSS & injeksi" },
    { name = "X-Frame-Options",            weight = 10, desc = "Clickjacking protection" },
    { name = "X-Content-Type-Options",     weight = 10, desc = "MIME sniffing protection" },
    { name = "Referrer-Policy",            weight = 8,  desc = "Kontrol kebocoran URL" },
    { name = "Permissions-Policy",         weight = 8,  desc = "Feature policy browser" },
    { name = "X-XSS-Protection",           weight = 5,  desc = "Browser XSS filter (legacy)" },
    { name = "Cross-Origin-Opener-Policy", weight = 7,  desc = "Cross-origin isolation" },
    { name = "Cross-Origin-Resource-Policy",weight= 7,  desc = "Cross-origin resource sharing" },
    { name = "Cache-Control",              weight = 5,  desc = "Caching directive" },
    { name = "Clear-Site-Data",            weight = 5,  desc = "Data clearing on logout" },
}

-- Header yang bisa membocorkan informasi sensitif
local LEAK_HEADERS = {
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
    "X-CF-Powered-By", "X-Runtime", "X-Version",
}

-- ── Helper Functions ─────────────────────────────────────────
local function header_get(response, name)
    -- Case-insensitive header lookup
    local lower_name = name:lower()
    for k, v in pairs(response.header) do
        if k:lower() == lower_name then
            return v
        end
    end
    return nil
end

local function check_hsts(value)
    local issues = {}
    if not value:match("max%-age=%d+") then
        table.insert(issues, "max-age tidak ditemukan")
    else
        local age = tonumber(value:match("max%-age=(%d+)"))
        if age and age < 31536000 then
            table.insert(issues, string.format("max-age terlalu pendek (%d < 31536000)", age))
        end
    end
    if not value:match("includeSubDomains") then
        table.insert(issues, "includeSubDomains tidak ada")
    end
    return issues
end

local function check_csp(value)
    local issues = {}
    if value:match("unsafe%-inline") then
        table.insert(issues, "BAHAYA: 'unsafe-inline' memungkinkan XSS")
    end
    if value:match("unsafe%-eval") then
        table.insert(issues, "BAHAYA: 'unsafe-eval' memungkinkan kode dinamis")
    end
    if value:match("%*") then
        table.insert(issues, "PERINGATAN: Wildcard '*' terlalu permisif")
    end
    if not value:match("default%-src") and not value:match("script%-src") then
        table.insert(issues, "Tidak ada default-src atau script-src")
    end
    return issues
end

local function check_cors(value)
    if value == "*" then
        return {"BAHAYA: Access-Control-Allow-Origin: * mengizinkan semua origin"}
    end
    return {}
end

local function analyze_cookies(response)
    local results = {}
    local cookies = response.header["set-cookie"]
    if not cookies then return results end

    -- Bisa multiple Set-Cookie headers
    local cookie_list = type(cookies) == "table" and cookies or {cookies}
    for _, cookie in ipairs(cookie_list) do
        local name = cookie:match("^([^=]+)=")
        local issues = {}

        if not cookie:lower():match("secure") then
            table.insert(issues, "missing Secure flag")
        end
        if not cookie:lower():match("httponly") then
            table.insert(issues, "missing HttpOnly flag")
        end
        if not cookie:lower():match("samesite") then
            table.insert(issues, "missing SameSite flag (CSRF risk)")
        end

        if #issues > 0 and name then
            table.insert(results, string.format("Cookie '%s': %s",
                name:gsub("%s",""), table.concat(issues, ", ")))
        end
    end
    return results
end

-- ── Action ───────────────────────────────────────────────────
action = function(host, port)
    local path = stdnse.get_script_args("http-security-audit.path") or "/"

    -- Kirim request HEAD → fallback GET
    local response = http.head(host, port, path, {
        header = { ["User-Agent"] = "Mozilla/5.0 (Nmap NSE http-security-audit)" }
    })

    if not response or response.status == nil then
        return stdnse.format_output(false, "Tidak dapat terhubung ke target")
    end

    -- Jika HEAD tidak didukung, pakai GET
    if response.status == 405 then
        response = http.get(host, port, path)
    end

    local output    = stdnse.output_table()
    local score     = 0
    local max_score = 0
    local present   = {}
    local missing   = {}
    local warnings  = {}

    -- ── 1. Audit Security Headers ─────────────────────────────
    for _, h in ipairs(SECURITY_HEADERS) do
        max_score = max_score + h.weight
        local val = header_get(response, h.name)

        if val then
            score = score + h.weight
            table.insert(present, string.format("[✓] %s: %s", h.name, val:sub(1,80)))

            -- Deep validation
            local issues = {}
            if h.name == "Strict-Transport-Security" then
                issues = check_hsts(val)
            elseif h.name == "Content-Security-Policy" then
                issues = check_csp(val)
            end
            for _, issue in ipairs(issues) do
                table.insert(warnings, string.format("  ⚠ %s → %s", h.name, issue))
            end
        else
            table.insert(missing, string.format("[✗] %s — MISSING (%s)", h.name, h.desc))
        end
    end

    -- ── 2. Informasi Bocor dari Headers ───────────────────────
    local leaks = {}
    for _, lh in ipairs(LEAK_HEADERS) do
        local val = header_get(response, lh)
        if val then
            table.insert(leaks, string.format("%s: %s", lh, val))
        end
    end

    -- ── 3. CORS Check ─────────────────────────────────────────
    local acao = header_get(response, "Access-Control-Allow-Origin")
    if acao then
        local cors_issues = check_cors(acao)
        for _, ci in ipairs(cors_issues) do
            table.insert(warnings, ci)
        end
    end

    -- ── 4. Cookie Audit ───────────────────────────────────────
    local cookie_issues = analyze_cookies(response)
    for _, ci in ipairs(cookie_issues) do
        table.insert(warnings, "Cookie: " .. ci)
    end

    -- ── 5. Clickjacking ───────────────────────────────────────
    local xfo = header_get(response, "X-Frame-Options")
    local csp = header_get(response, "Content-Security-Policy")
    local has_frame_protection = xfo or (csp and csp:match("frame%-ancestors"))
    if not has_frame_protection then
        table.insert(warnings, "BAHAYA: Tidak ada perlindungan Clickjacking (X-Frame-Options / CSP frame-ancestors)")
    end

    -- ── Build Output ──────────────────────────────────────────
    local pct   = math.floor(score / max_score * 100)
    local grade = pct >= 90 and "A" or pct >= 75 and "B" or pct >= 60 and "C" or pct >= 40 and "D" or "F"

    output["Status"]        = string.format("HTTP %d", response.status)
    output["Security Score"] = string.format("%d/100 (Grade: %s)", pct, grade)

    if #present > 0 then
        output["Headers Present"] = present
    end
    if #missing > 0 then
        output["Headers Missing"] = missing
    end
    if #warnings > 0 then
        output["Security Warnings"] = warnings
    end
    if #leaks > 0 then
        output["Info Disclosure"] = leaks
    end

    -- Rekomendasi prioritas
    local reco = {}
    if not header_get(response, "Content-Security-Policy") then
        table.insert(reco, "Segera tambahkan Content-Security-Policy untuk mencegah XSS")
    end
    if not header_get(response, "Strict-Transport-Security") and port.number == 443 then
        table.insert(reco, "Aktifkan HSTS dengan max-age minimal 1 tahun")
    end
    if not header_get(response, "X-Frame-Options") then
        table.insert(reco, "Tambahkan X-Frame-Options: DENY untuk mencegah Clickjacking")
    end
    if #leaks > 0 then
        table.insert(reco, "Sembunyikan informasi server/teknologi dari response headers")
    end

    if #reco > 0 then
        output["Recommendations"] = reco
    end

    return output
end
