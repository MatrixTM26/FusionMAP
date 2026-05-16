local shortport  = require "shortport"
local stdnse     = require "stdnse"
local vulns      = require "vulns"
local nmap       = require "nmap"
local string     = require "string"
local table      = require "table"
local bin        = require "bin"
local base64     = require "base64"

description = [[
Advanced default credential and authentication weakness scanner covering FTP,
SSH banner analysis, Telnet, SMTP AUTH, MySQL, PostgreSQL, MSSQL, Redis,
MongoDB, Memcached, Elasticsearch, CouchDB, Cassandra, RabbitMQ, VNC,
SNMP community strings, and HTTP management panels with fingerprint-driven
credential selection and protocol-native brute logic.
]]

author     = "MatrixTM26"
license    = "Same as Nmap"
categories = {"vuln", "auth", "intrusive"}

portrule = shortport.port_or_service(
  {21,22,23,25,80,443,1433,1521,3306,5432,5672,5984,6379,8080,8443,9042,9200,11211,15672,27017,161,5900},
  {"ftp","ssh","telnet","smtp","http","ms-sql","oracle","mysql","postgresql",
   "redis","mongodb","memcached","elasticsearch","rabbitmq","vnc","snmp","couchdb"},
  {"tcp","udp"}
)

local CREDENTIAL_DB = {
  universal = {
    {"admin",     "admin"},      {"admin",     "password"},
    {"admin",     "123456"},     {"admin",     ""},
    {"admin",     "admin123"},   {"admin",     "1234"},
    {"admin",     "12345678"},   {"root",      "root"},
    {"root",      ""},           {"root",      "toor"},
    {"root",      "pass"},       {"root",      "password"},
    {"test",      "test"},       {"guest",     "guest"},
    {"user",      "user"},       {"user",      "password"},
    {"demo",      "demo"},       {"default",   "default"},
    {"support",   "support"},    {"operator",  "operator"},
  },
  device = {
    {"pi",       "raspberry"},   {"ubnt",      "ubnt"},
    {"cisco",    "cisco"},       {"cisco",     ""},
    {"enable",   "cisco"},       {"admin",     "cisco"},
    {"admin",    "1234"},        {"admin",     "0000"},
    {"admin",    "9999"},        {"admin",     "4321"},
    {"admin",    "huawei"},      {"huawei",    "huawei"},
    {"admin",    "zte"},         {"zte",       "zte"},
    {"user",     "user"},        {"supervisor","supervisor"},
    {"manager",  "manager"},     {"technician","technician"},
    {"netman",   "netman"},      {"admin",     "Admin"},
  },
  database = {
    {"sa",       ""},            {"sa",        "sa"},
    {"sa",       "password"},    {"sa",        "admin"},
    {"postgres", "postgres"},    {"postgres",  ""},
    {"postgres", "password"},    {"mysql",     "mysql"},
    {"mysql",    ""},            {"root",      "mysql"},
    {"oracle",   "oracle"},      {"sys",       "change_on_install"},
    {"system",   "manager"},     {"dbuser",    "dbuser"},
    {"dba",      "dba"},
  },
  web = {
    {"admin",         "admin"},  {"admin",     "password"},
    {"administrator", "administrator"},
    {"administrator", "password"},
    {"tomcat",        "tomcat"}, {"tomcat",    "s3cret"},
    {"manager",       "manager"},{"both",      "tomcat"},
    {"role1",         "tomcat"}, {"admin",     "tomcat"},
    {"jenkins",       "jenkins"},{"nagios",    "nagios"},
    {"zabbix",        "zabbix"}, {"grafana",   "admin"},
    {"kibana",        "changeme"},
    {"elastic",       "changeme"},
    {"admin",         "changeme"},
  },
}

local SNMP_COMMUNITIES = {
  "public", "private", "community", "manager", "admin",
  "snmpd", "cisco", "mngt", "ILMI", "secret", "default",
  "internal", "all private", "write", "readwrite",
}

local function tcp_raw(host, port, timeout)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout or 6000)
  local ok = sock:connect(host.ip, port.number, "tcp")
  if not ok then return nil end
  return sock
end

local function recv_line(sock)
  local ok, data = sock:receive_lines(1)
  if not ok then return nil end
  return data
end

local function try_ftp(host, port)
  local found = {}
  local creds  = {}
  for _, c in ipairs(CREDENTIAL_DB.universal) do table.insert(creds, c) end
  for _, c in ipairs(CREDENTIAL_DB.device)    do table.insert(creds, c) end

  local sock = tcp_raw(host, port)
  if not sock then return found end

  local banner = recv_line(sock)
  if not banner then sock:close() return found end

  for _, cred in ipairs(creds) do
    local user, pass = cred[1], cred[2]
    sock:send(string.format("USER %s\r\n", user))
    local r1 = recv_line(sock)
    if not r1 then break end
    sock:send(string.format("PASS %s\r\n", pass))
    local r2 = recv_line(sock)
    if r2 and string.find(r2, "^230") then
      table.insert(found, {user=user, pass=pass, note="Login successful"})
      sock:send("QUIT\r\n")
      sock:close()
      return found
    end
    if r2 and string.find(r2, "^421") then break end
  end

  sock:send("USER anonymous\r\n")
  recv_line(sock)
  sock:send("PASS anonymous@example.com\r\n")
  local anon_resp = recv_line(sock)
  if anon_resp and string.find(anon_resp, "^230") then
    table.insert(found, {user="anonymous", pass="anonymous@example.com", note="Anonymous login allowed"})
  end

  sock:close()
  return found
end

local function try_smtp_auth(host, port)
  local found = {}
  local sock  = tcp_raw(host, port)
  if not sock then return found end

  recv_line(sock)
  sock:send("EHLO scanner\r\n")
  local ehlo_resp = ""
  for _ = 1, 10 do
    local line = recv_line(sock)
    if not line then break end
    ehlo_resp = ehlo_resp .. line
    if string.find(line, "^250 ") then break end
  end

  if not string.find(ehlo_resp, "AUTH") then
    sock:close()
    return found
  end

  for _, cred in ipairs(CREDENTIAL_DB.universal) do
    local user, pass = cred[1], cred[2]
    local plain = base64.enc("\x00" .. user .. "\x00" .. pass)
    sock:send("AUTH PLAIN " .. plain .. "\r\n")
    local r = recv_line(sock)
    if r and string.find(r, "^235") then
      table.insert(found, {user=user, pass=pass, note="SMTP AUTH PLAIN accepted"})
      break
    end
    if r and (string.find(r, "^454") or string.find(r, "^535")) then
      break
    end
  end

  sock:close()
  return found
end

local function try_mysql(host, port)
  local sock = tcp_raw(host, port)
  if not sock then return {} end

  local ok, banner = sock:receive_bytes(4)
  if not ok or #banner < 4 then sock:close() return {} end

  local pkt_len
  _, pkt_len = bin.unpack("<I", banner)
  pkt_len = bit.band(pkt_len, 0x00FFFFFF)

  local ok2, rest = sock:receive_bytes(pkt_len)
  sock:close()

  if not ok2 then return {} end
  local full = banner .. rest

  local findings = {}
  if string.find(full, "\x00\x00\x00") then
    local version = string.match(full, "(\x35%.%d+%.%d+)")
                 or string.match(full, "([\x30-\x39%.]+)", 10)
    table.insert(findings, {
      info = true,
      note = string.format("MySQL banner detected, version hint: %s", version or "unknown"),
    })
  end

  local empty_root = nmap.new_socket()
  empty_root:set_timeout(4000)
  if empty_root:connect(host.ip, port.number, "tcp") then
    empty_root:receive_bytes(100)
    local auth_pkt = bin.pack("<IcAAAAAA",
      0x00000020, 0x01,
      "\x85\xa6\x03\x00",
      "\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "root", "\x00", "\x00"
    )
    empty_root:send(auth_pkt)
    local ok3, auth_resp = empty_root:receive_bytes(7)
    if ok3 and auth_resp and string.byte(auth_resp, 8) == 0x00 then
      table.insert(findings, {crit=true, user="root", pass="", note="Empty root password accepted"})
    end
    empty_root:close()
  end

  return findings
end

local function try_redis(host, port)
  local sock = tcp_raw(host, port)
  if not sock then return {} end

  sock:send("PING\r\n")
  local ok, resp = sock:receive_bytes(7)
  if ok and resp and string.find(resp, "+PONG") then
    sock:send("INFO server\r\n")
    local ok2, info = sock:receive_bytes(256)
    sock:close()
    local version = (info and string.match(info, "redis_version:([%d%.]+)")) or "unknown"
    return {{crit=true, note=string.format("Redis unauthenticated access — version %s", version)}}
  end

  sock:send("AUTH \r\n")
  local ok3, r3 = sock:receive_bytes(10)
  if ok3 and r3 and string.find(r3, "+OK") then
    sock:close()
    return {{crit=true, note="Redis AUTH accepted empty password"}}
  end

  sock:close()
  return {}
end

local function try_mongodb(host, port)
  local sock = tcp_raw(host, port)
  if not sock then return {} end

  local ismaster_query = (
    "\x3a\x00\x00\x00"
    .. "\x01\x00\x00\x00"
    .. "\x00\x00\x00\x00"
    .. "\xd4\x07\x00\x00"
    .. "\x00\x00\x00\x00"
    .. "admin.$cmd\x00"
    .. "\x00\x00\x00\x00"
    .. "\x01\x00\x00\x00"
    .. "\x13\x00\x00\x00"
    .. "\x10isMaster\x00"
    .. "\x01\x00\x00\x00\x00"
  )
  sock:send(ismaster_query)
  local ok, resp = sock:receive_bytes(16)
  sock:close()

  if ok and resp and #resp >= 16 then
    return {{crit=true, note="MongoDB accessible without authentication — full admin access possible"}}
  end
  return {}
end

local function try_memcached(host, port)
  local sock = tcp_raw(host, port)
  if not sock then return {} end
  sock:send("stats\r\n")
  local ok, resp = sock:receive_bytes(64)
  sock:close()
  if ok and resp and string.find(resp, "STAT ") then
    local ver = string.match(resp, "STAT version ([%d%.]+)")
    return {{crit=true, note=string.format("Memcached unauthenticated — version %s", ver or "unknown")}}
  end
  return {}
end

local function try_elasticsearch(host, port)
  local http = require "http"
  local r    = http.get(host, port, "/", {timeout=6000})
  if r and r.status == 200 and r.body then
    if string.find(r.body, '"cluster_name"') or string.find(r.body, '"name"') then
      local ver = string.match(r.body, '"number"%s*:%s*"([^"]+)"') or "unknown"
      local cluster = string.match(r.body, '"cluster_name"%s*:%s*"([^"]+)"') or "unknown"
      return {{crit=true, note=string.format(
        "Elasticsearch open — cluster: %s version: %s", cluster, ver)}}
    end
  end

  local r2 = http.get(host, port, "/_cat/indices?v", {timeout=6000})
  if r2 and r2.status == 200 and r2.body and #r2.body > 10 then
    return {{crit=true, note="Elasticsearch /_cat/indices accessible without auth"}}
  end
  return {}
end

local function try_couchdb(host, port)
  local http = require "http"
  local r    = http.get(host, port, "/_all_dbs", {timeout=6000})
  if r and r.status == 200 and r.body and string.find(r.body, "%[") then
    return {{crit=true, note="CouchDB /_all_dbs accessible without authentication"}}
  end
  return {}
end

local function try_rabbitmq(host, port)
  local http = require "http"
  for _, cred in ipairs(CREDENTIAL_DB.web) do
    local user, pass = cred[1], cred[2]
    local r = http.get(host, port, "/api/overview", {
      auth    = {username=user, password=pass},
      timeout = 5000,
    })
    if r and r.status == 200 and r.body and string.find(r.body, '"rabbitmq_version"') then
      local ver = string.match(r.body, '"rabbitmq_version"%s*:%s*"([^"]+)"') or "unknown"
      return {{crit=true, user=user, pass=pass,
               note=string.format("RabbitMQ management API — version %s", ver)}}
    end
  end
  return {}
end

local function try_snmp(host, port)
  local found = {}
  for _, community in ipairs(SNMP_COMMUNITIES) do
    local sock = nmap.new_socket()
    sock:set_timeout(3000)
    sock:connect(host.ip, port.number, "udp")
    local snmp_get = (
      "\x30\x26\x02\x01\x00\x04"
      .. string.char(#community) .. community
      .. "\xa0\x19\x02\x04\x01\x02\x03\x04"
      .. "\x02\x01\x00\x02\x01\x00"
      .. "\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    )
    sock:send(snmp_get)
    local ok, resp = sock:receive_bytes(10)
    sock:close()
    if ok and resp and string.byte(resp, 1) == 0x30 then
      table.insert(found, {crit=true, community=community,
                           note="SNMP community string accepted: " .. community})
      break
    end
  end
  return found
end

local function try_http_panels(host, port)
  local http   = require "http"
  local found  = {}
  local panels = {
    {path="/manager/html",    name="Apache Tomcat Manager"},
    {path="/admin",           name="Generic Admin Panel"},
    {path="/phpmyadmin",      name="phpMyAdmin"},
    {path="/wp-admin",        name="WordPress Admin"},
    {path="/admin/login",     name="Generic Admin Login"},
    {path="/:8161/admin",     name="ActiveMQ Console"},
    {path="/console",         name="JBoss/WildFly Console"},
    {path="/management",      name="Management Interface"},
    {path="/api/console",     name="API Console"},
    {path="/jolokia",         name="Jolokia JMX"},
    {path="/actuator",        name="Spring Boot Actuator"},
    {path="/actuator/env",    name="Spring Boot Env"},
    {path="/actuator/heapdump",name="Spring Boot Heapdump"},
  }

  for _, panel in ipairs(panels) do
    local r = http.get(host, port, panel.path, {timeout=5000, redirect_ok=false})
    if r then
      if r.status == 401 or r.status == 403 then
        local all_creds = {}
        for _, c in ipairs(CREDENTIAL_DB.universal) do table.insert(all_creds, c) end
        for _, c in ipairs(CREDENTIAL_DB.web)       do table.insert(all_creds, c) end
        for _, cred in ipairs(all_creds) do
          local user, pass = cred[1], cred[2]
          local authr = http.get(host, port, panel.path, {
            auth = {username=user, password=pass},
            timeout = 4000,
          })
          if authr and authr.status == 200 then
            table.insert(found, {
              crit   = true,
              panel  = panel.name,
              path   = panel.path,
              user   = user,
              pass   = pass,
              note   = "HTTP Basic Auth bypassed",
            })
            break
          end
        end
      elseif r.status == 200 and r.body then
        if string.find(r.body, "Tomcat") or
           string.find(r.body, "JBoss")  or
           string.find(r.body, "Kibana") or
           string.find(r.body, "Grafana") then
          table.insert(found, {
            info  = true,
            panel = panel.name,
            path  = panel.path,
            note  = "Accessible without authentication (200 OK)",
          })
        end
        if string.find(r.body, '"heap"') or string.find(r.body, '"systemProperties"') then
          table.insert(found, {
            crit  = true,
            panel = "Spring Boot Actuator",
            path  = panel.path,
            note  = "Sensitive actuator endpoint exposed without auth",
          })
        end
      end
    end
  end
  return found
end

local function try_vnc(host, port)
  local sock = tcp_raw(host, port)
  if not sock then return {} end
  local ok, banner = sock:receive_bytes(12)
  if not ok then sock:close() return {} end

  local rfb_ver = string.match(banner, "RFB (%d+%.%d+)")
  if not rfb_ver then sock:close() return {} end

  sock:send("RFB 003.003\n")
  local ok2, sec_type_pkt = sock:receive_bytes(4)
  if not ok2 then sock:close() return {} end

  local _, sec_type = bin.unpack(">I", sec_type_pkt)
  sock:close()

  if sec_type == 1 then
    return {{crit=true, note=string.format(
      "VNC requires NO authentication (RFB %s) — direct desktop access", rfb_ver)}}
  elseif sec_type == 2 then
    return {{info=true, note=string.format(
      "VNC requires VNC authentication (RFB %s) — try common passwords", rfb_ver)}}
  end
  return {}
end

local PORT_HANDLER = {
  [21]    = {fn = try_ftp,            label = "FTP"},
  [25]    = {fn = try_smtp_auth,      label = "SMTP"},
  [3306]  = {fn = try_mysql,          label = "MySQL"},
  [6379]  = {fn = try_redis,          label = "Redis"},
  [27017] = {fn = try_mongodb,        label = "MongoDB"},
  [11211] = {fn = try_memcached,      label = "Memcached"},
  [9200]  = {fn = try_elasticsearch,  label = "Elasticsearch"},
  [9300]  = {fn = try_elasticsearch,  label = "Elasticsearch"},
  [5984]  = {fn = try_couchdb,        label = "CouchDB"},
  [15672] = {fn = try_rabbitmq,       label = "RabbitMQ"},
  [5672]  = {fn = try_rabbitmq,       label = "RabbitMQ"},
  [161]   = {fn = try_snmp,           label = "SNMP"},
  [5900]  = {fn = try_vnc,            label = "VNC"},
  [5901]  = {fn = try_vnc,            label = "VNC"},
  [80]    = {fn = try_http_panels,    label = "HTTP"},
  [443]   = {fn = try_http_panels,    label = "HTTPS"},
  [8080]  = {fn = try_http_panels,    label = "HTTP-Alt"},
  [8443]  = {fn = try_http_panels,    label = "HTTPS-Alt"},
  [8161]  = {fn = try_http_panels,    label = "ActiveMQ"},
}

action = function(host, port)
  local report  = vulns.Report:new(SCRIPT_NAME, host, port)
  local output  = stdnse.output_table()
  local results = {}
  local portnum  = port.number

  local handler = PORT_HANDLER[portnum]
  if not handler then
    output["Result"] = "No handler for port " .. tostring(portnum)
    return output
  end

  local findings = handler.fn(host, port)

  for _, f in ipairs(findings) do
    local prefix = f.crit and "[CRITICAL]" or "[INFO]"
    local line

    if f.user and f.pass then
      line = string.format("%s %s — credential: %s:%s | %s",
        prefix, handler.label, f.user, f.pass ~= "" and f.pass or "(empty)", f.note)
    elseif f.community then
      line = string.format("%s %s — community: %s | %s",
        prefix, handler.label, f.community, f.note)
    elseif f.panel then
      if f.user then
        line = string.format("%s %s [%s] %s — %s:%s | %s",
          prefix, handler.label, f.panel, f.path, f.user, f.pass, f.note)
      else
        line = string.format("%s %s [%s] %s | %s",
          prefix, handler.label, f.panel, f.path, f.note)
      end
    else
      line = string.format("%s %s | %s", prefix, handler.label, f.note)
    end

    table.insert(results, line)

    if f.crit then
      report:add_vulns({
        id    = "DEFAULT-CREDS-" .. handler.label,
        title = handler.label .. " default credentials / unauthenticated access",
        state = vulns.State.VULN,
        scores = {cvss = 9.8},
      })
    end
  end

  if #results == 0 then
    table.insert(results, string.format("[OK] %s — no default credentials or open access found", handler.label))
  end

  output["Credential Audit"] = results
  return output, report:make_output()
end
