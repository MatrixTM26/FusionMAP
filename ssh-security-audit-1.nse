-- ============================================================
-- ssh-security-audit.nse
-- Nmap NSE Script: SSH Configuration & Algorithm Security Audit
--
-- Usage:
--   nmap -p 22 --script ssh-security-audit <target>
--   nmap -p 22 --script ssh-security-audit \
--        --script-args ssh-security-audit.timeout=10 <target>
--
-- Author  : MatrixTM26
-- License : Same as Nmap--See https://nmap.org/book/man-legal.html
-- ============================================================

local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"

description = [[
Audits SSH server security configuration by analyzing:
  * SSH server version and known vulnerabilities
  * Cryptographic algorithms (KEX, cipher, MAC, HostKey)
  * Detection of weak/deprecated algorithms (MD5, RC4, DES, 3DES, Arcfour)
  * Potentially dangerous configurations
  * Hardening recommendations

This script only reads the banner and performs an initial SSH handshake
without authentication -- safe for auditing.

Banner reader uses a single blocking receive_bytes(256) call so it
works on slow servers and servers that require the client to speak
first (client-first mode, RFC 4253 s4.2).
]]

author     = "MatrixTM26"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(22, "ssh")

-- ── Weak/deprecated algorithm database ───────────────────────
local WEAK_KEX = {
    ["diffie-hellman-group1-sha1"]         = "CRITICAL: DH Group1 (768/1024-bit) -- CVE-2016-0777",
    ["diffie-hellman-group-exchange-sha1"] = "WEAK: SHA1 in KEX is deprecated",
    ["gss-gex-sha1-*"]                     = "WEAK: SHA1 in GSSAPI KEX",
    ["gss-group1-sha1-*"]                  = "CRITICAL: Group1 SHA1 GSSAPI",
}

local WEAK_CIPHERS = {
    ["arcfour"]                     = "CRITICAL: RC4 -- prohibited by RFC 8758",
    ["arcfour128"]                  = "CRITICAL: RC4-128 -- prohibited by RFC 8758",
    ["arcfour256"]                  = "CRITICAL: RC4-256 -- prohibited by RFC 8758",
    ["3des-cbc"]                    = "WEAK: 3DES-CBC -- Sweet32 attack (CVE-2016-2183)",
    ["blowfish-cbc"]                = "WEAK: Blowfish CBC -- 64-bit block size",
    ["cast128-cbc"]                 = "WEAK: CAST-128 CBC -- 64-bit block size",
    ["des-cbc"]                     = "CRITICAL: DES-CBC -- deprecated, 56-bit key",
    ["aes128-cbc"]                  = "WARNING: AES-CBC -- susceptible to BEAST attack",
    ["aes192-cbc"]                  = "WARNING: AES-CBC -- susceptible to BEAST attack",
    ["aes256-cbc"]                  = "WARNING: AES-CBC -- susceptible to BEAST attack",
    ["rijndael-cbc@lysator.liu.se"] = "WEAK: Rijndael CBC (AES-CBC alias)",
}

local WEAK_MACS = {
    ["hmac-md5"]            = "WEAK: HMAC-MD5 -- MD5 is not secure for MAC",
    ["hmac-md5-96"]         = "WEAK: HMAC-MD5-96 -- truncated MD5",
    ["hmac-sha1"]           = "WARNING: HMAC-SHA1 -- SHA1 deprecated",
    ["hmac-sha1-96"]        = "WARNING: HMAC-SHA1-96 -- truncated SHA1",
    ["hmac-ripemd160"]      = "WEAK: HMAC-RIPEMD160 -- deprecated",
    ["umac-32@openssh.com"] = "WARNING: UMAC-32 -- tag size too small",
}

local WEAK_HOSTKEYS = {
    ["ssh-dss"]             = "CRITICAL: DSA/DSS 1024-bit -- disabled in OpenSSH >= 7.0",
    ["ssh-rsa"]             = "WARNING: RSA-SHA1 -- disabled by default in OpenSSH >= 8.8",
    ["ecdsa-sha2-nistp256"] = "INFO: NIST P-256 -- potential NIST curve concern",
    ["ecdsa-sha2-nistp384"] = "INFO: NIST P-384 -- potential NIST curve concern",
    ["ecdsa-sha2-nistp521"] = "INFO: NIST P-521 -- potential NIST curve concern",
}

local GOOD_CIPHERS = {
    ["chacha20-poly1305@openssh.com"] = true,
    ["aes256-gcm@openssh.com"]        = true,
    ["aes128-gcm@openssh.com"]        = true,
    ["aes256-ctr"]                    = true,
    ["aes192-ctr"]                    = true,
    ["aes128-ctr"]                    = true,
}

local GOOD_MACS = {
    ["hmac-sha2-512-etm@openssh.com"] = true,
    ["hmac-sha2-256-etm@openssh.com"] = true,
    ["umac-128-etm@openssh.com"]      = true,
    ["hmac-sha2-512"]                 = true,
    ["hmac-sha2-256"]                 = true,
}

-- ── Packet helpers ────────────────────────────────────────────
local function read_uint32(data, pos)
    if pos + 3 > #data then return 0, pos + 4 end
    local a, b, c, d = data:byte(pos, pos + 3)
    return (a * 0x1000000) + (b * 0x10000) + (c * 0x100) + d, pos + 4
end

local function read_namelist(data, pos)
    if pos > #data then return {}, pos end
    local len, newpos = read_uint32(data, pos)
    if len == 0 then return {}, newpos end
    if newpos + len - 1 > #data then return {}, newpos end
    local raw = data:sub(newpos, newpos + len - 1)
    newpos = newpos + len
    local names = {}
    for name in raw:gmatch("[^,]+") do names[#names + 1] = name end
    return names, newpos
end

local function parse_kexinit(data)
    -- Buffer layout (1-based):
    --   bytes  1-4  : packet_length  (uint32)
    --   byte   5    : padding_length
    --   byte   6    : message type (20 = SSH_MSG_KEXINIT)
    --   bytes  7-22 : cookie (16 random bytes)
    --   byte  23+   : name-list fields begin
    local pos = 23
    local result = {}
    local fields = {
        "kex_algorithms", "server_host_key_algorithms",
        "encryption_c2s", "encryption_s2c",
        "mac_c2s",        "mac_s2c",
        "compression_c2s","compression_s2c",
    }
    for _, field in ipairs(fields) do
        if pos > #data then break end
        local names, newpos = read_namelist(data, pos)
        result[field] = names
        pos = newpos
    end
    return result
end

local function check_algorithms(alg_list, weak_db, good_db)
    local issues, good = {}, {}
    for _, alg in ipairs(alg_list or {}) do
        if weak_db[alg] then
            issues[#issues + 1] = ("[X] %-42s %s"):format(alg, weak_db[alg])
        elseif good_db and good_db[alg] then
            good[#good + 1] = "[+] " .. alg
        end
    end
    return issues, good
end

local function analyze_banner(banner)
    local issues, info = {}, {}
    local proto, sw = banner:match("SSH%-([%d%.]+)%-(.+)")
    if proto then
        info[#info + 1] = "Protocol: SSH-" .. proto
        if proto:match("^1%.") then
            issues[#issues + 1] =
                "CRITICAL: SSHv1 supported -- vulnerable to MITM and decryption"
        end
    end
    if sw then
        sw = sw:gsub("\r",""):gsub("\n","")
        info[#info + 1] = "Software: " .. sw
        local ver = sw:match("OpenSSH_([%d%.]+)")
        if ver then
            local maj, min = ver:match("^(%d+)%.(%d+)")
            maj, min = tonumber(maj), tonumber(min)
            if maj then
                if maj < 7 then
                    issues[#issues + 1] =
                        ("CRITICAL: OpenSSH %s is very old -- multiple critical CVEs"):format(ver)
                elseif maj == 7 and min < 4 then
                    issues[#issues + 1] =
                        ("WEAK: OpenSSH %s -- CVE-2016-6515, CVE-2016-10009"):format(ver)
                elseif maj < 8 then
                    issues[#issues + 1] =
                        ("WARNING: OpenSSH %s -- consider upgrading to 8.x+"):format(ver)
                else
                    info[#info + 1] =
                        ("OpenSSH %s (reasonably current)"):format(ver)
                end
            end
        end
        local db = sw:match("[Dd]ropbear_([%d%.]+)")
        if db then
            info[#info + 1] = "Dropbear SSH " .. db
            issues[#issues + 1] =
                "INFO: Dropbear -- verify no known CVEs for this version"
        end
        if sw:match("Cisco") then
            issues[#issues + 1] =
                "INFO: Cisco SSH -- check Cisco advisories for latest firmware"
        end
    end
    return issues, info
end

-- ── Robust SSH banner reader ──────────────────────────────────
--
-- FIX for "No SSH banner received (got: )":
--
-- Old code: loop receive_bytes(1) per character.
-- Problem:  per-call timeout burns on an empty pipe; returns
--           empty string before any data arrives.
--
-- New code:
--   Step 1 -- single blocking receive_bytes(256).
--             Blocks until ANY data arrives, then returns it all.
--   Step 2 -- if server is silent, send our client ID string first
--             (RFC 4253 s4.2 allows client-first).  Some strict
--             implementations or SSH proxies wait for the client
--             to identify itself before responding.
--   Step 3 -- search the buffer for "SSH-" regardless of any
--             pre-banner text ("Authorized use only.", etc.).
--
-- Returns: banner_string, client_id_already_sent (bool)
--
local function read_ssh_banner(socket, timeout_ms)
    local CLIENT_ID = "SSH-2.0-MatrixTM26_Audit\r\n"
    socket:set_timeout(timeout_ms)

    -- Step 1: server-first (most common)
    local ok, data = socket:receive_bytes(256)
    if ok and data then
        local line = data:match("(SSH%-[^\r\n]+)")
        if line then return line, false end
    end

    -- Step 2: client-first fallback
    socket:send(CLIENT_ID)
    socket:set_timeout(timeout_ms)
    ok, data = socket:receive_bytes(256)
    if ok and data then
        local line = data:match("(SSH%-[^\r\n]+)")
        if line then return line, true end
    end

    return nil, false
end

-- ── Main action ───────────────────────────────────────────────
action = function(host, port)
    local timeout_ms = (tonumber(
        stdnse.get_script_args("ssh-security-audit.timeout")) or 10) * 1000

    local socket = nmap.new_socket()
    socket:set_timeout(timeout_ms)

    local ok, err = socket:connect(host, port)
    if not ok then
        return stdnse.format_output(false,
            "Connection failed: " .. (err or "unknown"))
    end

    local banner, already_sent = read_ssh_banner(socket, timeout_ms)
    if not banner then
        socket:close()
        return stdnse.format_output(false, "No SSH banner received")
    end

    if not already_sent then
        socket:send("SSH-2.0-MatrixTM26_Audit\r\n")
    end

    -- Read KEXINIT (4-byte length prefix)
    socket:set_timeout(timeout_ms)
    local raw_len, _ = socket:receive_bytes(4)
    local kex_payload = nil

    if raw_len and #raw_len >= 4 then
        local pkt_len, _ = read_uint32(raw_len, 1)
        pkt_len = math.min(pkt_len, 35000)
        local kex_data, _ = socket:receive_bytes(pkt_len)
        if kex_data then kex_payload = raw_len .. kex_data end
    end
    socket:close()

    local output     = stdnse.output_table()
    local all_issues = {}

    output["SSH Banner"] = banner
    local b_issues, b_info = analyze_banner(banner)
    if #b_info > 0 then output["Server Info"] = b_info end
    for _, i in ipairs(b_issues) do all_issues[#all_issues + 1] = i end

    if kex_payload and #kex_payload > 22 then
        local pok, algs = pcall(parse_kexinit, kex_payload)
        if pok and algs then
            if algs.kex_algorithms and #algs.kex_algorithms > 0 then
                output["KEX Algorithms"] = algs.kex_algorithms
            end
            local ki, _ = check_algorithms(algs.kex_algorithms, WEAK_KEX, nil)
            for _, i in ipairs(ki) do all_issues[#all_issues+1]=i end

            if algs.encryption_s2c and #algs.encryption_s2c > 0 then
                output["Encryption Algorithms"] = algs.encryption_s2c
            end
            local ci, cg = check_algorithms(algs.encryption_s2c, WEAK_CIPHERS, GOOD_CIPHERS)
            if #cg > 0 then output["Strong Ciphers"] = cg end
            for _, i in ipairs(ci) do all_issues[#all_issues+1]=i end

            if algs.mac_s2c and #algs.mac_s2c > 0 then
                output["MAC Algorithms"] = algs.mac_s2c
            end
            local mi, mg = check_algorithms(algs.mac_s2c, WEAK_MACS, GOOD_MACS)
            if #mg > 0 then output["Strong MACs"] = mg end
            for _, i in ipairs(mi) do all_issues[#all_issues+1]=i end

            if algs.server_host_key_algorithms and #algs.server_host_key_algorithms > 0 then
                output["Host Key Types"] = algs.server_host_key_algorithms
            end
            local hi, _ = check_algorithms(algs.server_host_key_algorithms, WEAK_HOSTKEYS, nil)
            for _, i in ipairs(hi) do all_issues[#all_issues+1]=i end

            if algs.compression_s2c then
                for _, c in ipairs(algs.compression_s2c) do
                    if c == "zlib" then
                        all_issues[#all_issues+1] =
                            "WARNING: zlib compression enabled -- susceptible to CRIME-like attacks"
                    end
                end
                if #algs.compression_s2c > 0 then
                    output["Compression"] = algs.compression_s2c
                end
            end
        else
            output["KEXINIT"] = "Could not parse -- banner analysis only"
        end
    else
        output["KEXINIT"] = "Not received -- banner analysis only"
    end

    if #all_issues > 0 then
        output["Security Issues"] = all_issues
        local crit = 0
        for _, i in ipairs(all_issues) do
            if i:match("CRITICAL") then crit = crit + 1 end
        end
        output["Risk Level"] = crit > 0
            and ("HIGH (%d critical issue(s))"):format(crit)
            or  ("MEDIUM (%d issue(s))"):format(#all_issues)
    else
        output["Risk Level"] = "LOW -- No significant security issues found"
    end

    output["Hardening Tips"] = {
        "Allow only: chacha20-poly1305, aes256-gcm, aes128-gcm",
        "Use ETM MACs: hmac-sha2-256-etm, hmac-sha2-512-etm",
        "KEX: curve25519-sha256, diffie-hellman-group16-sha512",
        "Disable password authentication -- use key-based auth only",
        "Set PermitRootLogin no in sshd_config",
        "Use AllowUsers/AllowGroups to restrict access",
    }

    return output
end
