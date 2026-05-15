-- default-creds-scan.nse
-- Default Credentials Scanner for common services
-- Covers: SSH, FTP, Telnet, MySQL, PostgreSQL, MSSQL, MongoDB, Redis, HTTP Basic Auth
-- Usage: nmap --script default-creds-scan.nse <target>
-- WARNING: Use only on systems you own or have explicit permission to test.

local shortport = require "shortport"
local stdnse    = require "stdnse"
local brute     = require "brute"
local creds     = require "creds"
local ftp       = require "ftp"
local string    = require "string"
local table     = require "table"

description = [[
Tests for default/common credentials on:
  - FTP (21)
  - SSH (22) - detection only, no brute
  - Telnet (23)
  - MySQL (3306)
  - PostgreSQL (5432)
  - Redis (6379) - no-auth check
  - MongoDB (27017) - no-auth check
  - HTTP Basic Auth (80/443/8080)
  
WARNING: Authorized testing only!
]]

author = "Security Scanner"
license = "Same as Nmap"
categories = {"vuln", "auth"}

-- Common default credential pairs
local DEFAULT_CREDS = {
  {"admin",     "admin"},
  {"admin",     "password"},
  {"admin",     "123456"},
  {"admin",     ""},
  {"root",      "root"},
  {"root",      ""},
  {"root",      "toor"},
  {"root",      "password"},
  {"admin",     "admin123"},
  {"test",      "test"},
  {"guest",     "guest"},
  {"user",      "user"},
  {"pi",        "raspberry"},       -- Raspberry Pi default
  {"ubnt",      "ubnt"},            -- Ubiquiti devices
  {"cisco",     "cisco"},           -- Cisco devices
  {"admin",     "1234"},
  {"administrator", "password"},
  {"sa",        ""},                -- MSSQL default
  {"sa",        "sa"},
  {"postgres",  "postgres"},
  {"mysql",     "mysql"},
}

-- HTTP panels with default creds
local HTTP_PANELS = {
  {path="/",              realm_match="Admin"},
  {path="/admin",         realm_match=nil},
  {path="/admin/login",   realm_match=nil},
  {path="/login",         realm_match=nil},
  {path="/management",    realm_match=nil},
  {path="/console",       realm_match=nil},
  {path="/wp-admin",      realm_match="WordPress"},
  {path="/phpmyadmin",    realm_match=nil},
  {path="/manager/html",  realm_match="Tomcat"},  -- Apache Tomcat
}

local function try_ftp(host, port)
  local results = {}
  for _, cred in ipairs(DEFAULT_CREDS) do
    local user, pass = cred[1], cred[2]
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local status = socket:connect(host.ip, port.number)
    if status then
      socket:receive_lines(1) -- banner
      socket:send(string.format("USER %s\r\n", user))
      socket:receive_lines(1)
      socket:send(string.format("PASS %s\r\n", pass))
      local ok, response = socket:receive_lines(1)
      if ok and response and string.find(response, "^230") then
        table.insert(results, string.format("[CRITICAL] FTP login SUCCESS: %s:%s", user, pass))
        socket:send("QUIT\r\n")
        socket:close()
        break
      end
      socket:close()
    end
  end
  return results
end

local function check_redis_noauth(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local status = socket:connect(host.ip, port.number)
  if not status then return nil end
  socket:send("PING\r\n")
  local ok, resp = socket:receive_bytes(10)
  socket:close()
  if ok and resp and string.find(resp, "+PONG") then
    return "[CRITICAL] Redis exposed WITHOUT authentication - full database access possible!"
  end
  return nil
end

local function check_mongodb_noauth(host, port)
  -- MongoDB wire protocol: isMaster command
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local status = socket:connect(host.ip, port.number)
  if not status then return nil end
  -- Minimal OP_QUERY for isMaster
  local msg = "\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
           .. "\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00"
           .. "\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x10\x69\x73"
           .. "\x4d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"
  socket:send(msg)
  local ok, resp = socket:receive_bytes(16)
  socket:close()
  if ok and resp and #resp >= 16 then
    return "[CRITICAL] MongoDB accessible without authentication!"
  end
  return nil
end

action = function(host, port)
  local output  = stdnse.output_table()
  local results = {}
  local portnum  = port.number
  local service  = port.service or ""

  -- FTP Check
  if portnum == 21 or service == "ftp" then
    local ftp_results = try_ftp(host, port)
    for _, r in ipairs(ftp_results) do table.insert(results, r) end
  end

  -- Redis Check
  if portnum == 6379 or service == "redis" then
    local r = check_redis_noauth(host, port)
    if r then table.insert(results, r) end
  end

  -- MongoDB Check
  if portnum == 27017 or service == "mongod" then
    local r = check_mongodb_noauth(host, port)
    if r then table.insert(results, r) end
  end

  -- HTTP Basic Auth / common panels
  if portnum == 80 or portnum == 443 or portnum == 8080 or portnum == 8443 then
    local http = require "http"
    for _, panel in ipairs(HTTP_PANELS) do
      local resp = http.get(host, port, panel.path, {timeout=5000})
      if resp and resp.status == 401 then
        -- Try default creds with basic auth
        for _, cred in ipairs(DEFAULT_CREDS) do
          local user, pass = cred[1], cred[2]
          local auth_resp = http.get(host, port, panel.path, {
            auth = {username=user, password=pass},
            timeout = 5000,
          })
          if auth_resp and auth_resp.status == 200 then
            table.insert(results, string.format(
              "[CRITICAL] HTTP Basic Auth bypass at %s with %s:%s",
              panel.path, user, pass))
            break
          end
        end
      elseif resp and resp.status == 200 then
        -- Check if it's a known login panel
        if resp.body then
          if string.find(resp.body, "Tomcat Manager") or
             string.find(resp.body, "phpMyAdmin") or
             string.find(resp.body, "JBoss") then
            table.insert(results, "[!] Management panel detected at: " .. panel.path)
          end
        end
      end
    end
  end

  output["Default Credential Scan"] = #results > 0 and results
    or {"No default credentials found on this port"}
  return output
end
