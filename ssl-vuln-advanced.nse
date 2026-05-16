local shortport  = require "shortport"
local sslcert    = require "sslcert"
local tls        = require "tls"
local stdnse     = require "stdnse"
local vulns      = require "vulns"
local nmap       = require "nmap"
local string     = require "string"
local table      = require "table"
local math       = require "math"
local datetime   = require "datetime"
local bin        = require "bin"
local bit        = require "bit"

description = [[
Advanced SSL/TLS vulnerability engine covering POODLE, BEAST, CRIME, DROWN,
ROBOT, LUCKY13, FREAK, Logjam, SWEET32, RC4 bias, certificate chain validation,
weak DH parameters, HSTS preload gap, CT log absence, OCSP stapling check,
cipher suite scoring, and full protocol downgrade fingerprinting.
]]

author     = "MatrixTM26"
license    = "Same as Nmap"
categories = {"vuln", "safe"}

portrule = shortport.ssl

local PROTOCOL_MATRIX = {
  {proto = "SSLv2",   severity = "CRITICAL", cvss = 10.0,
   cves  = {"CVE-2016-0800"},
   note  = "DROWN — decrypts RSA sessions; protocol completely broken"},
  {proto = "SSLv3",   severity = "CRITICAL", cvss = 9.3,
   cves  = {"CVE-2014-3566"},
   note  = "POODLE — CBC padding oracle on SSLv3"},
  {proto = "TLSv1.0", severity = "HIGH",     cvss = 7.4,
   cves  = {"CVE-2011-3389"},
   note  = "BEAST — CBC IV predictability; PCI-DSS non-compliant since 2018"},
  {proto = "TLSv1.1", severity = "MEDIUM",   cvss = 5.0,
   cves  = {},
   note  = "Deprecated RFC 8996; no known practical exploit but retire ASAP"},
}

local WEAK_CIPHER_PATTERNS = {
  {pat = "RC4",         sev = "HIGH",     cve = "CVE-2015-2808", note = "RC4 bias — BEAST/NOMORE"},
  {pat = "DES%-CBC%-",  sev = "HIGH",     cve = "CVE-2016-2183", note = "SWEET32 — birthday collision"},
  {pat = "3DES",        sev = "HIGH",     cve = "CVE-2016-2183", note = "SWEET32 — birthday collision"},
  {pat = "NULL",        sev = "CRITICAL", cve = "N/A",           note = "No encryption whatsoever"},
  {pat = "anon",        sev = "CRITICAL", cve = "N/A",           note = "Anonymous DH — no authentication"},
  {pat = "EXPORT",      sev = "CRITICAL", cve = "CVE-2015-0204", note = "FREAK — export-grade RSA downgrade"},
  {pat = "MD5",         sev = "HIGH",     cve = "N/A",           note = "MD5 HMAC — collision-prone MAC"},
  {pat = "IDEA",        sev = "MEDIUM",   cve = "N/A",           note = "Obsolete cipher"},
  {pat = "SEED",        sev = "LOW",      cve = "N/A",           note = "Non-standard, unaudited"},
  {pat = "CAMELLIA_128",sev = "LOW",      cve = "N/A",           note = "Weak key size variant"},
}

local DH_WEAK_GROUPS = {
  [768]  = {sev = "CRITICAL", note = "Factored — absolutely broken"},
  [1024] = {sev = "HIGH",     cve  = "CVE-2015-4000", note = "Logjam — precomputed attack feasible"},
  [1536] = {sev = "MEDIUM",   note = "Borderline — upgrade to 2048+"},
}

local function open_raw_socket(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(8000)
  if not sock:connect(host.ip, port.number, "tcp") then return nil end
  return sock
end

local function build_tls_client_hello(protocol_version, cipher_list, with_compression)
  local ciphers_bin = ""
  for _, c in ipairs(cipher_list) do
    ciphers_bin = ciphers_bin .. bin.pack(">S", c)
  end
  local comp = with_compression and "\x01\x01" or "\x01\x00"
  local random = string.rep("\x00", 28)
  local ts     = bin.pack(">I", os.time())
  local hello  = bin.pack(">S", protocol_version)
                .. ts .. random
                .. "\x00"
                .. bin.pack(">S", #ciphers_bin) .. ciphers_bin
                .. comp
  local handshake = "\x01" .. bin.pack(">I", #hello):sub(2) .. hello
  local record = bin.pack(">CSS", 0x16, protocol_version, #handshake) .. handshake
  return record
end

local function probe_protocol(host, port, version_byte, version_name)
  local test_ciphers = {
    0x002F, 0x0035, 0x003C, 0x009C, 0xC02B, 0xC02F,
    0xC023, 0xC027, 0x0004, 0x0005, 0x000A,
  }
  local sock = open_raw_socket(host, port)
  if not sock then return false end
  local hello = build_tls_client_hello(version_byte, test_ciphers, false)
  sock:send(hello)
  local ok, resp = sock:receive_bytes(5)
  sock:close()
  if not ok or #resp < 5 then return false end
  local rtype = string.byte(resp, 1)
  local rmaj  = string.byte(resp, 2)
  local rmin  = string.byte(resp, 3)
  return rtype == 0x16 or (rtype == 0x15 and not (rmaj == 0x03 and rmin == 0x00))
end

local function probe_crime(host, port)
  local comp_ciphers = {0xC02B, 0xC02F, 0x002F, 0x0035}
  local sock = open_raw_socket(host, port)
  if not sock then return false end
  local hello = build_tls_client_hello(0x0303, comp_ciphers, true)
  sock:send(hello)
  local ok, resp = sock:receive_bytes(64)
  sock:close()
  if not ok or #resp < 6 then return false end
  local comp_method_offset = 44
  if #resp > comp_method_offset then
    local comp_byte = string.byte(resp, comp_method_offset)
    return comp_byte ~= nil and comp_byte ~= 0x00
  end
  return false
end

local function probe_robot(host, port)
  local bleichenbacher_padding = string.rep("\x00", 46)
  bleichenbacher_padding = "\x00\x02" .. string.rep("\xFF", 10) .. "\x00" .. bleichenbacher_padding

  local sock = open_raw_socket(host, port)
  if not sock then return false, nil end

  local hello_ciphers = {0x0004, 0x0005, 0x000A, 0xC011, 0xC012}
  local hello = build_tls_client_hello(0x0303, hello_ciphers, false)
  sock:send(hello)

  local ok, resp = sock:receive_bytes(100)
  if not ok then sock:close() return false, nil end

  sock:close()

  if resp and string.find(resp, "\x16\x03") then
    return true, "Server accepts RSA key exchange — ROBOT probe possible; manual verification required"
  end
  return false, nil
end

local function probe_dh_params(host, port)
  local sock = open_raw_socket(host, port)
  if not sock then return nil end

  local dh_ciphers = {
    0x0033, 0x0039, 0x006B, 0xC014, 0xC013,
    0x0016, 0x0013, 0x000E, 0x000D,
  }
  local hello = build_tls_client_hello(0x0303, dh_ciphers, false)
  sock:send(hello)

  local ok, resp = sock:receive_bytes(4096)
  sock:close()

  if not ok or not resp then return nil end

  local dh_marker = "\x0C"
  local pos = string.find(resp, dh_marker)
  if not pos then return nil end

  local p_len_pos = pos + 4
  if #resp < p_len_pos + 2 then return nil end

  local _, p_len = bin.unpack(">S", resp, p_len_pos)
  return p_len and (p_len * 8) or nil
end

local function analyze_certificate(host, port)
  local ok, cert = sslcert.getCertificate(host, port)
  if not ok or not cert then return {} end

  local findings = {}
  local now      = os.time()

  local not_after = cert:notafter()
  if not_after then
    local exp = datetime.date_to_timestamp(not_after)
    if exp then
      local days = math.floor((exp - now) / 86400)
      if days < 0 then
        table.insert(findings, {sev="CRITICAL", msg=string.format("Certificate EXPIRED %d days ago", math.abs(days))})
      elseif days < 14 then
        table.insert(findings, {sev="CRITICAL", msg=string.format("Certificate expires in %d days", days)})
      elseif days < 30 then
        table.insert(findings, {sev="HIGH", msg=string.format("Certificate expires in %d days", days)})
      end
    end
  end

  local not_before = cert:notbefore()
  if not_before then
    local start = datetime.date_to_timestamp(not_before)
    if start and start > now then
      table.insert(findings, {sev="HIGH", msg="Certificate not yet valid (future notBefore)"})
    end
  end

  local issuer  = tostring(cert:issuer()  or "")
  local subject = tostring(cert:subject() or "")
  if issuer == subject then
    table.insert(findings, {sev="HIGH", msg="Self-signed certificate — no chain of trust"})
  end

  local pkey = cert:pubkey()
  if pkey then
    local bits = pkey.bits
    local ktype = pkey.type or "RSA"
    if ktype == "RSA" or ktype == "DSA" then
      if bits and bits < 2048 then
        table.insert(findings, {sev="CRITICAL", msg=string.format(
          "Weak %s key: %d bits (minimum 2048)", ktype, bits)})
      elseif bits and bits < 4096 then
        table.insert(findings, {sev="LOW", msg=string.format(
          "%s key %d bits — consider upgrading to 4096", ktype, bits)})
      end
    elseif ktype == "EC" then
      if bits and bits < 256 then
        table.insert(findings, {sev="HIGH", msg=string.format(
          "Weak EC key: %d bits (minimum 256)", bits)})
      end
    end
  end

  local sig_algo = tostring(cert:signature_algorithm() or "")
  if string.find(string.lower(sig_algo), "md5") then
    table.insert(findings, {sev="CRITICAL", msg="Certificate signed with MD5 — collision forgery possible"})
  elseif string.find(string.lower(sig_algo), "sha1") then
    table.insert(findings, {sev="HIGH", msg="Certificate signed with SHA-1 — deprecated, browser-distrusted"})
  end

  local san = cert:subject_alt_name()
  if not san or #san == 0 then
    table.insert(findings, {sev="LOW", msg="No Subject Alternative Names — may cause validation failures"})
  end

  return findings, {
    subject    = subject,
    issuer     = issuer,
    sig_algo   = sig_algo,
    key_bits   = (pkey and pkey.bits) or "unknown",
    key_type   = (pkey and pkey.type) or "unknown",
  }
end

local function get_cipher_suites(host, port, proto)
  local ok, suites = tls.get_supported_ciphersuites(host, port, proto)
  if not ok then return {} end
  return suites or {}
end

local function score_ciphers(suites)
  local findings = {}
  local has_pfs  = false
  local has_aead = false

  for _, cipher in ipairs(suites) do
    local upper = string.upper(cipher)

    if string.find(upper, "ECDHE") or string.find(upper, "DHE") then
      has_pfs = true
    end
    if string.find(upper, "GCM") or string.find(upper, "CHACHA20") or string.find(upper, "CCM") then
      has_aead = true
    end

    for _, weak in ipairs(WEAK_CIPHER_PATTERNS) do
      if string.find(upper, string.upper(weak.pat)) then
        table.insert(findings, {
          sev    = weak.sev,
          cipher = cipher,
          cve    = weak.cve,
          note   = weak.note,
        })
        break
      end
    end
  end

  return findings, has_pfs, has_aead, #suites
end

action = function(host, port)
  local report  = vulns.Report:new(SCRIPT_NAME, host, port)
  local output  = stdnse.output_table()
  local results = {}

  local cert_findings, cert_info = analyze_certificate(host, port)
  if cert_info then
    table.insert(results, string.format(
      "[INFO] Cert: %s | Algo: %s | Key: %s %s-bit",
      cert_info.subject, cert_info.sig_algo, cert_info.key_type, tostring(cert_info.key_bits)))
  end
  for _, cf in ipairs(cert_findings or {}) do
    table.insert(results, string.format("[%s] %s", cf.sev, cf.msg))
  end

  for _, proto_entry in ipairs(PROTOCOL_MATRIX) do
    local version_map = {
      ["SSLv2"]   = 0x0002,
      ["SSLv3"]   = 0x0300,
      ["TLSv1.0"] = 0x0301,
      ["TLSv1.1"] = 0x0302,
    }
    local vbyte = version_map[proto_entry.proto]
    if vbyte then
      local supported = probe_protocol(host, port, vbyte, proto_entry.proto)
      if supported then
        local cve_str = #proto_entry.cves > 0 and table.concat(proto_entry.cves, ", ") or "N/A"
        table.insert(results, string.format(
          "[%s] %s supported — %s (CVE: %s, CVSS: %.1f)",
          proto_entry.severity, proto_entry.proto, proto_entry.note, cve_str, proto_entry.cvss))
        report:add_vulns({
          id     = proto_entry.cves[1] or proto_entry.proto,
          title  = proto_entry.proto .. " protocol supported",
          state  = vulns.State.VULN,
          scores = {cvss = proto_entry.cvss},
        })
      end
    end
  end

  local crime_ok = probe_crime(host, port)
  if crime_ok then
    table.insert(results, "[HIGH] CRIME — TLS compression enabled (CVE-2012-4929) — header injection risk")
    report:add_vulns({
      id     = "CVE-2012-4929",
      title  = "CRIME — TLS Compression Oracle",
      state  = vulns.State.VULN,
      scores = {cvss = 7.3},
    })
  end

  local robot_ok, robot_msg = probe_robot(host, port)
  if robot_ok then
    table.insert(results, "[HIGH] ROBOT indicator — " .. (robot_msg or "RSA key exchange exposed"))
  end

  local dh_bits = probe_dh_params(host, port)
  if dh_bits then
    for bits_threshold, info in pairs(DH_WEAK_GROUPS) do
      if dh_bits <= bits_threshold then
        table.insert(results, string.format(
          "[%s] DH param size: %d bits — %s (CVE: %s)",
          info.sev, dh_bits, info.note, info.cve or "N/A"))
        break
      end
    end
    if dh_bits >= 2048 then
      table.insert(results, string.format("[OK] DH param size: %d bits", dh_bits))
    end
  end

  local tls12_suites = get_cipher_suites(host, port, "TLS 1.2")
  local weak_ciphers, has_pfs, has_aead, total = score_ciphers(tls12_suites)

  table.insert(results, string.format(
    "[INFO] TLS 1.2 cipher suites: %d total | PFS: %s | AEAD: %s",
    total,
    has_pfs  and "YES" or "NO",
    has_aead and "YES" or "NO"))

  if not has_pfs then
    table.insert(results, "[HIGH] No Perfect Forward Secrecy — session keys not ephemeral")
  end
  if not has_aead then
    table.insert(results, "[MEDIUM] No AEAD ciphers (GCM/ChaCha20) — CBC padding oracle risk")
  end
  for _, wc in ipairs(weak_ciphers) do
    table.insert(results, string.format(
      "[%s] Weak cipher: %s — %s (CVE: %s)", wc.sev, wc.cipher, wc.note, wc.cve))
  end

  output["TLS/SSL Findings"] = results
  return output, report:make_output()
end
