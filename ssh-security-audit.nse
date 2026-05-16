-- ============================================================
-- ssh-security-audit.nse
-- Nmap NSE Script: SSH Configuration & Algorithm Security Audit
--
-- Penggunaan:
--   nmap -p 22 --script ssh-security-audit <target>
--   nmap -p 22 --script ssh-security-audit --script-args ssh-security-audit.timeout=5 <target>
--
-- Author : LuaNetSec Project
-- License: Same as Nmap
-- ============================================================

local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

description = [[
Mengaudit konfigurasi keamanan SSH server dengan menganalisis:
  * Versi SSH server dan potensi kerentanan
  * Algoritma kriptografi yang digunakan (KEX, cipher, MAC, HostKey)
  * Deteksi algoritma lemah/deprecated (MD5, RC4, DES, 3DES, Arcfour)
  * Konfigurasi yang berpotensi berbahaya
  * Rekomendasi hardening

Script ini HANYA membaca banner dan melakukan SSH handshake awal
tanpa autentikasi — AMAN digunakan untuk audit.
]]

author     = "LuaNetSec"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(22, "ssh")

-- ── Weak/Deprecated Algorithms Database ──────────────────────
local WEAK_KEX = {
    ["diffie-hellman-group1-sha1"]    = "KRITIS: DH Group1 (768/1024-bit) — CVE-2016-0777",
    ["diffie-hellman-group-exchange-sha1"] = "LEMAH: SHA1 di KEX sudah deprecated",
    ["gss-gex-sha1-*"]                = "LEMAH: SHA1 di GSSAPI KEX",
    ["gss-group1-sha1-*"]             = "KRITIS: Group1 SHA1 GSSAPI",
}

local WEAK_CIPHERS = {
    ["arcfour"]    = "KRITIS: RC4 — dilarang oleh RFC 8758",
    ["arcfour128"] = "KRITIS: RC4-128 — dilarang oleh RFC 8758",
    ["arcfour256"] = "KRITIS: RC4-256 — dilarang oleh RFC 8758",
    ["3des-cbc"]   = "LEMAH: 3DES-CBC — Sweet32 attack (CVE-2016-2183)",
    ["blowfish-cbc"] = "LEMAH: Blowfish CBC — block size 64-bit",
    ["cast128-cbc"]  = "LEMAH: CAST-128 CBC — block size 64-bit",
    ["des-cbc"]    = "KRITIS: DES-CBC — deprecated, kunci 56-bit",
    ["aes128-cbc"] = "PERINGATAN: AES-CBC rentan terhadap BEAST attack",
    ["aes192-cbc"] = "PERINGATAN: AES-CBC rentan terhadap BEAST attack",
    ["aes256-cbc"] = "PERINGATAN: AES-CBC rentan terhadap BEAST attack",
    ["rijndael-cbc@lysator.liu.se"] = "LEMAH: Rijndael CBC (alias AES-CBC)",
}

local WEAK_MACS = {
    ["hmac-md5"]         = "LEMAH: HMAC-MD5 — MD5 tidak aman untuk MAC",
    ["hmac-md5-96"]      = "LEMAH: HMAC-MD5-96 — truncated MD5",
    ["hmac-sha1"]        = "PERINGATAN: HMAC-SHA1 — SHA1 deprecated",
    ["hmac-sha1-96"]     = "PERINGATAN: HMAC-SHA1-96 — truncated SHA1",
    ["hmac-ripemd160"]   = "LEMAH: HMAC-RIPEMD160 — deprecated",
    ["umac-32@openssh.com"] = "PERINGATAN: UMAC-32 — tag size terlalu kecil",
}

local WEAK_HOSTKEYS = {
    ["ssh-dss"]        = "KRITIS: DSA/DSS 1024-bit — dinonaktifkan OpenSSH >= 7.0",
    ["ssh-rsa"]        = "PERINGATAN: RSA-SHA1 — OpenSSH >= 8.8 nonaktif secara default",
    ["ecdsa-sha2-nistp256"] = "INFO: NIST P-256 — potensial backdoor NIST curve",
    ["ecdsa-sha2-nistp384"] = "INFO: NIST P-384 — potensial backdoor NIST curve",
    ["ecdsa-sha2-nistp521"] = "INFO: NIST P-521 — potensial backdoor NIST curve",
}

-- Algoritma yang AMAN & DIREKOMENDASIKAN
local GOOD_CIPHERS = {
    ["chacha20-poly1305@openssh.com"] = true,
    ["aes256-gcm@openssh.com"]        = true,
    ["aes128-gcm@openssh.com"]        = true,
    ["aes256-ctr"]                    = true,
    ["aes192-ctr"]                    = true,
    ["aes128-ctr"]                    = true,
}

local GOOD_MACS = {
    ["hmac-sha2-512-etm@openssh.com"]  = true,
    ["hmac-sha2-256-etm@openssh.com"]  = true,
    ["umac-128-etm@openssh.com"]       = true,
    ["hmac-sha2-512"]                  = true,
    ["hmac-sha2-256"]                  = true,
}

-- ── SSH Handshake Parser ──────────────────────────────────────
-- Membaca SSH_MSG_KEXINIT packet untuk mendapatkan daftar algoritma

local SSH2_MSG_KEXINIT = 20
local function read_uint32(data, pos)
    local a, b, c, d = data:byte(pos, pos+3)
    return (a * 0x1000000) + (b * 0x10000) + (c * 0x100) + d, pos + 4
end

local function read_namelist(data, pos)
    local len, newpos = read_uint32(data, pos)
    if not len then return {}, pos end
    local names_str = data:sub(newpos, newpos + len - 1)
    newpos = newpos + len
    local names = {}
    for name in names_str:gmatch("[^,]+") do
        table.insert(names, name)
    end
    return names, newpos
end

local function parse_kexinit(data)
    -- Skip: packet_length(4) + padding_length(1) + msg_type(1) + cookie(16)
    local pos = 4 + 1 + 1 + 16 + 1  -- +1 for 1-based index

    local result = {}
    local fields = {
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
    }

    for _, field in ipairs(fields) do
        local names, newpos = read_namelist(data, pos)
        result[field] = names
        pos = newpos
        if pos > #data then break end
    end

    return result
end

local function check_algorithms(alg_list, weak_db, good_db)
    local issues  = {}
    local good    = {}
    local neutral = {}

    for _, alg in ipairs(alg_list or {}) do
        if weak_db[alg] then
            table.insert(issues, string.format("  ✗ %-40s → %s", alg, weak_db[alg]))
        elseif good_db and good_db[alg] then
            table.insert(good, "  ✓ " .. alg)
        else
            table.insert(neutral, "    " .. alg)
        end
    end

    return issues, good, neutral
end

-- ── Analyze SSH Banner ────────────────────────────────────────
local function analyze_banner(banner)
    local issues = {}
    local info   = {}

    -- Extract version
    local proto, sw_ver = banner:match("SSH%-([%d%.]+)-(.+)")
    if proto then
        table.insert(info, "Protocol: SSH-" .. proto)
        if proto == "1.99" or proto == "1.5" or proto:match("^1%.") then
            table.insert(issues, "KRITIS: Mendukung SSHv1 — rentan terhadap MITM dan dekripsi")
        end
    end

    -- Detect software
    if sw_ver then
        table.insert(info, "Software: " .. sw_ver:gsub("\r",""):gsub("\n",""))

        -- OpenSSH version checks
        local openssh_ver = sw_ver:match("OpenSSH_([%d%.]+)")
        if openssh_ver then
            local major, minor = openssh_ver:match("^(%d+)%.(%d+)")
            major, minor = tonumber(major), tonumber(minor)
            if major and minor then
                if major < 7 then
                    table.insert(issues, string.format("KRITIS: OpenSSH %s sangat lama — banyak CVE kritis", openssh_ver))
                elseif major == 7 and minor < 4 then
                    table.insert(issues, string.format("LEMAH: OpenSSH %s — CVE-2016-6515 (DoS), CVE-2016-10009", openssh_ver))
                elseif major < 8 then
                    table.insert(issues, string.format("PERINGATAN: OpenSSH %s — pertimbangkan upgrade ke 8.x+", openssh_ver))
                else
                    table.insert(info, string.format("OpenSSH %s (relatif terkini)", openssh_ver))
                end
            end
        end

        -- Dropbear
        local db_ver = sw_ver:match("dropbear_([%d%.]+)")
        if db_ver then
            table.insert(info, "Dropbear SSH " .. db_ver)
            table.insert(issues, "INFO: Dropbear — verifikasi apakah versi ini memiliki CVE yang diketahui")
        end

        -- Cisco
        if sw_ver:match("Cisco") then
            table.insert(issues, "INFO: Cisco SSH — periksa advisory Cisco untuk firmware terkini")
        end
    end

    return issues, info
end

-- ── Main Action ───────────────────────────────────────────────
action = function(host, port)
    local timeout = tonumber(stdnse.get_script_args("ssh-security-audit.timeout")) or 8

    local socket = nmap.new_socket()
    socket:set_timeout(timeout * 1000)

    local status, err = socket:connect(host, port)
    if not status then
        return stdnse.format_output(false, "Koneksi gagal: " .. (err or "unknown"))
    end

    -- ── Baca banner ───────────────────────────────────────────
    local banner_line, _ = socket:receive_lines(1)
    if not banner_line then
        socket:close()
        return stdnse.format_output(false, "Tidak menerima banner SSH")
    end

    local banner = banner_line:gsub("\r\n",""):gsub("\n","")
    if not banner:match("^SSH%-") then
        socket:close()
        return stdnse.format_output(false, "Bukan SSH server: " .. banner:sub(1,50))
    end

    -- Kirim banner kita
    socket:send("SSH-2.0-LuaNetSec_Audit_1.0\r\n")

    -- ── Baca SSH_MSG_KEXINIT dari server ──────────────────────
    -- SSH packet: uint32 length, byte padding_length, byte msg_type, ...
    local raw_len_data, _ = socket:receive_bytes(4)
    if not raw_len_data or #raw_len_data < 4 then
        socket:close()
        -- Return banner analysis only
        local output = stdnse.output_table()
        output["Banner"]  = banner
        output["Warning"] = "Tidak dapat membaca KEXINIT packet — analisis terbatas"
        return output
    end

    local pkt_len, _ = read_uint32(raw_len_data, 1)
    pkt_len = math.min(pkt_len, 35000) -- safety cap

    local kex_data, _ = socket:receive_bytes(pkt_len)
    socket:close()

    -- ── Parse & Analyze ───────────────────────────────────────
    local output  = stdnse.output_table()
    local all_issues = {}

    -- Banner
    output["SSH Banner"] = banner
    local b_issues, b_info = analyze_banner(banner)
    if #b_info   > 0 then output["Server Info"] = b_info end
    if #b_issues > 0 then
        for _, i in ipairs(b_issues) do table.insert(all_issues, i) end
    end

    -- Parse KEXINIT jika data tersedia
    if kex_data and #kex_data > 20 then
        local combined = raw_len_data .. kex_data
        local ok, algs = pcall(parse_kexinit, combined)

        if ok and algs then
            -- KEX
            local kex_issues, kex_good, _ = check_algorithms(
                algs.kex_algorithms, WEAK_KEX, nil)
            if algs.kex_algorithms then
                output["KEX Algorithms"] = algs.kex_algorithms
            end
            for _, i in ipairs(kex_issues) do table.insert(all_issues, i) end

            -- Ciphers
            local cip_issues, cip_good, _ = check_algorithms(
                algs.encryption_algorithms_server_to_client, WEAK_CIPHERS, GOOD_CIPHERS)
            if algs.encryption_algorithms_server_to_client then
                output["Encryption Algorithms"] = algs.encryption_algorithms_server_to_client
            end
            if #cip_good > 0 then output["Good Ciphers"] = cip_good end
            for _, i in ipairs(cip_issues) do table.insert(all_issues, i) end

            -- MACs
            local mac_issues, mac_good, _ = check_algorithms(
                algs.mac_algorithms_server_to_client, WEAK_MACS, GOOD_MACS)
            if algs.mac_algorithms_server_to_client then
                output["MAC Algorithms"] = algs.mac_algorithms_server_to_client
            end
            if #mac_good > 0 then output["Good MACs"] = mac_good end
            for _, i in ipairs(mac_issues) do table.insert(all_issues, i) end

            -- Host Keys
            local hk_issues, _, _ = check_algorithms(
                algs.server_host_key_algorithms, WEAK_HOSTKEYS, nil)
            if algs.server_host_key_algorithms then
                output["Host Key Types"] = algs.server_host_key_algorithms
            end
            for _, i in ipairs(hk_issues) do table.insert(all_issues, i) end

            -- Compression
            local comp = algs.compression_algorithms_server_to_client
            if comp then
                for _, c in ipairs(comp) do
                    if c == "zlib" then
                        table.insert(all_issues,
                            "PERINGATAN: zlib compression aktif — rentan CRIME-like attack")
                    end
                end
                output["Compression"] = comp
            end
        end
    end

    -- ── Summary ───────────────────────────────────────────────
    if #all_issues > 0 then
        output["Security Issues"] = all_issues
        local kritis = 0
        for _, i in ipairs(all_issues) do
            if i:match("KRITIS") then kritis = kritis + 1 end
        end
        output["Risk Level"] = kritis > 0 and
            string.format("TINGGI (%d isu kritis)", kritis) or
            string.format("SEDANG (%d isu)", #all_issues)
    else
        output["Risk Level"] = "RENDAH — Tidak ada isu keamanan signifikan ditemukan"
    end

    -- Rekomendasi
    local reco = {
        "Gunakan only: chacha20-poly1305, aes256-gcm, aes128-gcm",
        "Gunakan ETM MAC: hmac-sha2-256-etm, hmac-sha2-512-etm",
        "KEX: curve25519-sha256, diffie-hellman-group16-sha512",
        "Nonaktifkan password auth — gunakan hanya key-based auth",
        "Batasi akses root: PermitRootLogin no",
        "Gunakan AllowUsers/AllowGroups untuk membatasi akses",
    }
    output["Hardening Tips"] = reco

    return output
end
