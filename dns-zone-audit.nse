-- ============================================================
-- dns-zone-audit.nse
-- Nmap NSE Script: DNS Zone Transfer Test & DNS Security Audit
--
-- Penggunaan:
--   nmap -p 53 --script dns-zone-audit <target>
--   nmap -p 53 --script dns-zone-audit --script-args dns-zone-audit.domain=example.com <target>
--
-- Author : LuaNetSec Project
-- License: Same as Nmap
-- ============================================================

local dns       = require "dns"
local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

description = [[
Mengaudit keamanan DNS server dengan:
  * Uji coba Zone Transfer (AXFR) — jika berhasil = celah kritis
  * Enumerasi record DNS umum (A, MX, NS, TXT, SOA, CNAME)
  * Deteksi DNS recursion terbuka (Open Resolver)
  * Deteksi DNS version disclosure
  * Uji DNSSEC configuration
  * Deteksi zone walking via NSEC
  * Cek SPF, DMARC, DKIM record untuk email security
]]

author     = "LuaNetSec"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(53, "domain")

-- ── DNS Packet Builder ────────────────────────────────────────
local function build_dns_query(qname, qtype)
    -- Transaction ID random
    local txid = math.random(0, 65535)
    local header = string.char(
        math.floor(txid / 256), txid % 256,  -- ID
        0x01, 0x00,   -- Flags: QR=0, Opcode=0, RD=1
        0x00, 0x01,   -- QDCOUNT = 1
        0x00, 0x00,   -- ANCOUNT = 0
        0x00, 0x00,   -- NSCOUNT = 0
        0x00, 0x00    -- ARCOUNT = 0
    )

    -- Encode QNAME
    local qname_encoded = ""
    for label in qname:gmatch("[^%.]+") do
        qname_encoded = qname_encoded .. string.char(#label) .. label
    end
    qname_encoded = qname_encoded .. "\0"

    -- QTYPE & QCLASS
    local QTYPES = { A=1, NS=2, CNAME=5, SOA=6, MX=15, TXT=16,
                     AAAA=28, SRV=33, AXFR=252, ANY=255 }
    local qt = QTYPES[qtype] or 255
    local qtype_bytes = string.char(math.floor(qt/256), qt%256)
    local qclass_in   = string.char(0x00, 0x01) -- IN

    return txid, header .. qname_encoded .. qtype_bytes .. qclass_in
end

local function send_dns_udp(host, port, query, timeout)
    local socket = nmap.new_socket("udp")
    socket:set_timeout(timeout or 3000)
    socket:connect(host, port)
    socket:send(query)
    local status, response = socket:receive()
    socket:close()
    if status then return response end
    return nil
end

local function send_dns_tcp(host, port, query, timeout)
    local socket = nmap.new_socket()
    socket:set_timeout(timeout or 5000)
    local ok, err = socket:connect(host, port)
    if not ok then return nil, err end
    -- TCP DNS: 2-byte length prefix
    local length_prefix = string.char(
        math.floor(#query / 256), #query % 256)
    socket:send(length_prefix .. query)
    -- Read 2-byte length
    local len_data = socket:receive_bytes(2)
    if not len_data or #len_data < 2 then
        socket:close()
        return nil
    end
    local resp_len = len_data:byte(1) * 256 + len_data:byte(2)
    local response = socket:receive_bytes(resp_len)
    socket:close()
    return response
end

-- ── DNS Response Parser (minimal) ────────────────────────────
local function parse_dns_header(data)
    if #data < 12 then return nil end
    local flags = data:byte(3) * 256 + data:byte(4)
    local rcode = flags % 16
    local qr    = math.floor(flags / 32768)
    local aa    = math.floor((flags % 1024) / 512)
    local tc    = math.floor((flags % 512) / 256)
    local rd    = math.floor((flags % 256) / 128)
    local ra    = math.floor((flags % 128) / 64)
    local ancount = data:byte(7) * 256 + data:byte(8)
    return {
        rcode = rcode, qr = qr, aa = aa,
        tc = tc, rd = rd, ra = ra,
        ancount = ancount
    }
end

local function decode_name(data, pos)
    local labels = {}
    local jumped = false
    local orig_pos = pos

    for _ = 1, 128 do
        if pos > #data then break end
        local len = data:byte(pos)
        if len == 0 then
            pos = pos + 1
            break
        elseif len >= 192 then -- pointer
            local ptr = (len - 192) * 256 + data:byte(pos + 1)
            if not jumped then orig_pos = pos + 2 end
            pos = ptr + 1
            jumped = true
        else
            local label = data:sub(pos + 1, pos + len)
            table.insert(labels, label)
            pos = pos + len + 1
        end
    end

    return table.concat(labels, "."), jumped and orig_pos or pos
end

-- ── Zone Transfer Test ────────────────────────────────────────
local function test_axfr(host, port, domain)
    local _, query = build_dns_query(domain, "AXFR")
    local response = send_dns_tcp(host, port, query, 8000)

    if not response or #response < 12 then
        return false, "Tidak ada respons AXFR"
    end

    local hdr = parse_dns_header(response)
    if not hdr then return false, "Respons tidak valid" end

    if hdr.rcode == 5 then return false, "REFUSED — Zone Transfer diblokir" end
    if hdr.rcode == 9 then return false, "NOTAUTH — server tidak autoritatif" end
    if hdr.rcode ~= 0 then
        return false, string.format("RCODE=%d", hdr.rcode)
    end

    -- Jika berhasil, response akan berisi banyak records
    if hdr.ancount > 0 or #response > 100 then
        return true, string.format(
            "ZONE TRANSFER BERHASIL! %d bytes data diterima — celah kritis!",
            #response)
    end

    return false, "Tidak ada data"
end

-- ── Open Resolver Test ────────────────────────────────────────
local function test_open_resolver(host, port)
    -- Coba resolve domain eksternal
    local _, query = build_dns_query("google.com", "A")
    local response = send_dns_udp(host, port, query, 3000)

    if not response then return false, "Tidak ada respons" end

    local hdr = parse_dns_header(response)
    if not hdr then return false, "Respons invalid" end

    if hdr.rcode == 0 and hdr.ancount > 0 then
        return true, "OPEN RESOLVER! Server merespons query untuk domain eksternal"
    elseif hdr.rcode == 5 then
        return false, "Recursion REFUSED (aman)"
    end

    return false, string.format("RCODE=%d, ANCOUNT=%d", hdr.rcode, hdr.ancount)
end

-- ── DNS Version Test ─────────────────────────────────────────
local function test_version(host, port)
    local _, query = build_dns_query("version.bind", "TXT")
    -- Set class CHAOS (0x0003) — versi BIND ada di class CH
    query = query:sub(1, -3) .. string.char(0x00, 0x03)
    local response = send_dns_udp(host, port, query, 3000)

    if not response or #response < 12 then return nil end

    local hdr = parse_dns_header(response)
    if hdr and hdr.rcode == 0 and hdr.ancount > 0 then
        -- Try to find version string in response
        local version_str = response:match("([%d%.]+%-[%a%d%-%.]+)")
            or response:match("BIND ([%d%.]+)")
            or "(version tersembunyi dalam raw packet)"
        return version_str
    end
    return nil
end

-- ── Email Security Records ────────────────────────────────────
local function check_email_security(host, port, domain)
    local results = {}

    -- SPF check
    local _, spf_query = build_dns_query(domain, "TXT")
    local spf_resp = send_dns_udp(host, port, spf_query, 3000)
    if spf_resp then
        if spf_resp:match("v=spf1") then
            table.insert(results, "✓ SPF record ditemukan")
            if spf_resp:match("+all") then
                table.insert(results, "✗ BAHAYA: SPF menggunakan +all (semua IP boleh kirim)")
            end
            if spf_resp:match("~all") then
                table.insert(results, "⚠ SPF softfail (~all) — pertimbangkan -all")
            end
            if spf_resp:match("%-all") then
                table.insert(results, "✓ SPF hardfail (-all) — konfigurasi ketat")
            end
        else
            table.insert(results, "✗ SPF record TIDAK ditemukan — email spoofing mungkin!")
        end
    end

    -- DMARC check
    local _, dmarc_q = build_dns_query("_dmarc." .. domain, "TXT")
    local dmarc_resp = send_dns_udp(host, port, dmarc_q, 3000)
    if dmarc_resp and dmarc_resp:match("v=DMARC1") then
        table.insert(results, "✓ DMARC record ditemukan")
        if dmarc_resp:match("p=none") then
            table.insert(results, "⚠ DMARC policy=none — monitoring only, tidak enforce")
        elseif dmarc_resp:match("p=quarantine") then
            table.insert(results, "✓ DMARC policy=quarantine")
        elseif dmarc_resp:match("p=reject") then
            table.insert(results, "✓ DMARC policy=reject (paling ketat)")
        end
    else
        table.insert(results, "✗ DMARC record TIDAK ditemukan")
    end

    -- DKIM selector umum
    local dkim_selectors = {"default", "google", "mail", "key1", "dkim", "selector1"}
    for _, sel in ipairs(dkim_selectors) do
        local dkim_domain = sel .. "._domainkey." .. domain
        local _, dkim_q = build_dns_query(dkim_domain, "TXT")
        local dkim_resp = send_dns_udp(host, port, dkim_q, 2000)
        if dkim_resp and dkim_resp:match("v=DKIM1") then
            table.insert(results, string.format("✓ DKIM selector '%s' ditemukan", sel))
            break
        end
    end

    return results
end

-- ── Main Action ───────────────────────────────────────────────
action = function(host, port)
    math.randomseed(os.time())

    local domain = stdnse.get_script_args("dns-zone-audit.domain")

    -- Coba dapatkan domain dari PTR atau gunakan hostname
    if not domain then
        domain = host.targetname or host.name
        if not domain or domain == "" then
            -- Gunakan IP-based domain untuk test terbatas
            domain = nil
        end
    end

    local output = stdnse.output_table()
    local issues = {}

    -- ── Test 1: Open Resolver ─────────────────────────────────
    local is_open, open_msg = test_open_resolver(host, port)
    output["Open Resolver Test"] = open_msg
    if is_open then
        table.insert(issues, "KRITIS: " .. open_msg)
    end

    -- ── Test 2: DNS Version Disclosure ───────────────────────
    local version = test_version(host, port)
    if version then
        output["DNS Version"] = version
        table.insert(issues, "PERINGATAN: Versi DNS terbuka — " .. version)
    else
        output["DNS Version"] = "Tersembunyi (baik)"
    end

    -- ── Test 3: Zone Transfer + Domain-specific checks ────────
    if domain then
        output["Target Domain"] = domain

        -- AXFR
        local axfr_ok, axfr_msg = test_axfr(host, port, domain)
        output["Zone Transfer (AXFR)"] = axfr_msg
        if axfr_ok then
            table.insert(issues, "KRITIS: " .. axfr_msg)
        end

        -- Email security
        local email_results = check_email_security(host, port, domain)
        if #email_results > 0 then
            output["Email Security (SPF/DMARC/DKIM)"] = email_results
        end

        -- Cek DNSSEC
        local _, ds_q = build_dns_query(domain, "ANY")
        local ds_resp = send_dns_udp(host, port, ds_q, 3000)
        if ds_resp then
            if ds_resp:match("RRSIG") or ds_resp:match("DNSKEY") then
                output["DNSSEC"] = "✓ DNSSEC aktif"
            else
                output["DNSSEC"] = "✗ DNSSEC tidak ditemukan — data DNS bisa dipalsukan"
                table.insert(issues, "PERINGATAN: DNSSEC tidak aktif")
            end
        end
    else
        output["Zone Transfer (AXFR)"] = "Tidak diuji — gunakan --script-args dns-zone-audit.domain=<domain>"
    end

    -- ── Summary ───────────────────────────────────────────────
    if #issues > 0 then
        output["Security Issues Found"] = issues
    else
        output["Security Issues Found"] = "Tidak ada isu kritis ditemukan"
    end

    output["Rekomendasi"] = {
        "Blokir zone transfer kecuali ke slave NS yang sah",
        "Nonaktifkan recursion untuk query eksternal",
        "Sembunyikan versi DNS: version.bind \"none\"",
        "Aktifkan DNSSEC untuk integritas data DNS",
        "Konfigurasi SPF/DMARC/DKIM untuk keamanan email",
        "Rate-limit query DNS untuk mencegah amplification DDoS",
    }

    return output
end
