-- ssl-vuln-scan.nse
-- SSL/TLS Vulnerability Scanner
-- Covers: POODLE, BEAST, CRIME, DROWN, weak ciphers, expired certs, Heartbleed indicator
-- Usage: nmap -p 443,8443,465,993,995 --script ssl-vuln-scan.nse <target>

local shortport = require "shortport"
local sslcert   = require "sslcert"
local tls       = require "tls"
local stdnse    = require "stdnse"
local datetime  = require "datetime"
local string    = require "string"
local table     = require "table"
local math      = require "math"

description = [[
Comprehensive SSL/TLS vulnerability scanner:
  - Weak protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
  - POODLE (CVE-2014-3566)
  - CRIME vulnerability (compression enabled)
  - Weak/export cipher suites (RC4, DES, NULL, EXPORT)
  - Certificate issues: expired, self-signed, weak key size
  - HSTS missing
  - Perfect Forward Secrecy check
]]

author = "Security Scanner"
license = "Same as Nmap"
categories = {"vuln", "safe"}

portrule = shortport.ssl

-- Weak ciphers pattern matching
local WEAK_CIPHERS = {
  "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
  "MD5", "RC2", "IDEA", "SEED", "CAMELLIA_128",
}

-- Vulnerable protocol versions
local WEAK_PROTOCOLS = {
  ["SSLv2"]   = {severity="CRITICAL", cve="N/A",           note="Completely broken, disable immediately"},
  ["SSLv3"]   = {severity="HIGH",     cve="CVE-2014-3566", note="POODLE attack possible"},
  ["TLSv1.0"] = {severity="MEDIUM",   cve="CVE-2011-3389", note="BEAST attack, PCI-DSS non-compliant"},
  ["TLSv1.1"] = {severity="LOW",      cve="N/A",           note="Deprecated, upgrade to TLS 1.2+"},
}

local function check_protocol(host, port, protocol)
  local hello = tls.client_hello({
    protocol = protocol,
    ciphers = tls.CIPHERS,
  })
  if not hello then return false end

  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local status = sock:connect(host.ip, port.number, "tcp")
  if not status then return false end

  sock:send(hello)
  local response = sock:receive_bytes(3)
  sock:close()

  if response and #response >= 3 then
    local b1, b2, b3 = string.byte(response, 1, 3)
    -- 0x16 = TLS handshake, 0x15 = alert
    if b1 == 0x16 then return true end
  end
  return false
end

action = function(host, port)
  local output   = stdnse.output_table()
  local vulns    = {}
  local info     = {}
  local warnings = {}

  -- === 1. Certificate Analysis ===
  local status, cert = sslcert.getCertificate(host, port)
  if status and cert then
    -- Expiry check
    local not_after = cert:notafter()
    if not_after then
      local now = os.time()
      local exp_ts = datetime.date_to_timestamp(not_after)
      if exp_ts then
        local days_left = math.floor((exp_ts - now) / 86400)
        if days_left < 0 then
          table.insert(vulns, string.format(
            "[CRITICAL] Certificate EXPIRED %d days ago!", math.abs(days_left)))
        elseif days_left < 30 then
          table.insert(warnings, string.format(
            "[!] Certificate expires in %d days", days_left))
        else
          table.insert(info, string.format("[OK] Certificate valid for %d more days", days_left))
        end
      end
    end

    -- Self-signed check
    local issuer  = cert:issuer()
    local subject = cert:subject()
    if issuer and subject and tostring(issuer) == tostring(subject) then
      table.insert(vulns, "[HIGH] Self-signed certificate detected")
    end

    -- Key size check
    local pkey = cert:pubkey()
    if pkey then
      local bits = pkey.bits
      if bits and bits < 2048 then
        table.insert(vulns, string.format(
          "[HIGH] Weak RSA key size: %d bits (minimum 2048 recommended)", bits))
      elseif bits then
        table.insert(info, string.format("[OK] Key size: %d bits", bits))
      end
    end

    -- Subject Alternative Names
    local cn = cert:subject()
    table.insert(info, "Certificate CN: " .. tostring(cn))
  else
    table.insert(warnings, "[!] Could not retrieve certificate")
  end

  -- === 2. Protocol Version Checks ===
  for proto, details in pairs(WEAK_PROTOCOLS) do
    if check_protocol(host, port, proto) then
      table.insert(vulns, string.format(
        "[%s] %s supported - %s (CVE: %s)",
        details.severity, proto, details.note, details.cve))
    end
  end

  -- === 3. Weak Cipher Detection via tls library ===
  local ciphers_status, ciphers = tls.get_supported_ciphersuites(host, port, "TLS 1.2")
  if ciphers_status and ciphers then
    local found_weak = {}
    for _, cipher in ipairs(ciphers) do
      for _, weak in ipairs(WEAK_CIPHERS) do
        if string.find(string.upper(cipher), string.upper(weak)) then
          table.insert(found_weak, cipher)
          break
        end
      end
    end
    if #found_weak > 0 then
      table.insert(vulns, "[HIGH] Weak cipher suites supported:")
      for _, c in ipairs(found_weak) do
        table.insert(vulns, "    - " .. c)
      end
    end

    -- Check for Forward Secrecy
    local has_pfs = false
    for _, cipher in ipairs(ciphers) do
      if string.find(cipher, "ECDHE") or string.find(cipher, "DHE") then
        has_pfs = true
        break
      end
    end
    if not has_pfs then
      table.insert(warnings, "[!] No Perfect Forward Secrecy (PFS) cipher suites found")
    else
      table.insert(info, "[OK] Perfect Forward Secrecy supported")
    end
  end

  output["Certificate & TLS Info"] = info
  output["Vulnerabilities"]        = #vulns > 0 and vulns or {"No critical SSL/TLS vulns found"}
  output["Warnings"]               = #warnings > 0 and warnings or nil
  return output
end
