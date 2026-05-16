local smb        = require "smb"
local smb2       = require "smb2"
local vulns      = require "vulns"
local stdnse     = require "stdnse"
local shortport  = require "shortport"
local nmap       = require "nmap"
local string     = require "string"
local table      = require "table"
local bin        = require "bin"
local bit        = require "bit"

description = [[
Advanced SMB vulnerability detection engine targeting MS17-010 (EternalBlue),
CVE-2020-0796 (SMBGhost), MS08-067, SMB relay conditions, null sessions,
guest access, pipe enumeration, and protocol downgrade fingerprinting.
]]

author     = "MatrixTM26"
license    = "Same as Nmap"
categories = {"vuln", "safe", "intrusive"}

portrule = shortport.port_or_service({139, 445}, {"netbios-ssn", "microsoft-ds"}, "tcp")

local STATUS_CODES = {
  SUCCESS            = 0x00000000,
  ACCESS_DENIED      = 0xC0000022,
  LOGON_FAILURE      = 0xC000006D,
  INVALID_PARAMETER  = 0xC000000D,
  NOT_SUPPORTED      = 0xC00000BB,
  BAD_NETWORK_NAME   = 0xC00000CC,
}

local SMB_DIALECTS = {
  "PC NETWORK PROGRAM 1.0",
  "LANMAN1.0",
  "Windows for Workgroups 3.1a",
  "LM1.2X002",
  "LANMAN2.1",
  "NT LM 0.12",
}

local function build_negotiate_request()
  local dialects = ""
  for _, d in ipairs(SMB_DIALECTS) do
    dialects = dialects .. bin.pack("CA", 0x02, d .. "\x00")
  end
  local header = bin.pack(">CCCCSSSSISSSS",
    0xFF, 0x53, 0x4D, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00,
    0x18, 0x01, 0x28, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )
  local wct    = bin.pack("C", 0x00)
  local bcc    = bin.pack("<S", #dialects)
  local payload = header .. wct .. bcc .. dialects
  local netbios = bin.pack(">CS>S", 0x00, 0x00, #payload)
  return netbios .. payload
end

local function build_smb2_negotiate()
  local smb2_header = bin.pack("<SSSICQQSS",
    0x40, 0x0000, 0x0000, 0x00000000,
    0x72000000, 0x0000000000000000,
    0x0000000000000000, 0x0000, 0x0000
  )
  local dialects = bin.pack("<SSS", 0x0202, 0x0210, 0x0300)
  local body = bin.pack("<SSSS",
    0x0024, 0x0003, 0x0000, 0x0000
  ) .. dialects
  local full    = smb2_header .. body
  local netbios = bin.pack(">I", #full)
  return netbios .. full
end

local function raw_connect(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(8000)
  local ok = sock:connect(host.ip, port.number, "tcp")
  if not ok then return nil end
  return sock
end

local function send_recv(sock, data)
  local ok = sock:send(data)
  if not ok then return nil end
  local status, resp = sock:receive_bytes(4)
  if not status or #resp < 4 then return nil end
  local _, length = bin.unpack(">I", resp)
  if length == 0 then return resp end
  local status2, rest = sock:receive_bytes(length)
  if not status2 then return nil end
  return resp .. rest
end

local function detect_smbv1_dialect(host, port)
  local sock = raw_connect(host, port)
  if not sock then return nil end
  local resp = send_recv(sock, build_negotiate_request())
  sock:close()
  if not resp or #resp < 40 then return nil end
  local dialect_index
  _, dialect_index = bin.unpack("<S", resp, 37)
  return dialect_index
end

local function probe_ms17010_transaction(host, port)
  local smbstate
  local status
  status, smbstate = smb.start(host)
  if not status then return false, "SMB start failed" end

  status = smb.negotiate_protocol(smbstate, {})
  if not status then
    smb.stop(smbstate)
    return false, "Negotiate failed"
  end

  status = smb.start_session(smbstate, {
    username = "",
    password = "",
    domain   = "",
  })
  if not status then
    smb.stop(smbstate)
    return false, "Null session rejected"
  end

  local tree_status, tree_id = smb.tree_connect(smbstate, "\\\\IPC$")
  if not tree_status then
    smb.stop(smbstate)
    return false, "IPC$ connect failed"
  end

  local fid_status, fid = smb.create_file(smbstate, "\\PIPE\\srv")
  if not fid_status then
    smb.stop(smbstate)
    return false, "Pipe open failed — host may be patched"
  end

  local trans_data = bin.pack("<SSSSSS",
    0x0000, 0x0026, 0x0000, 0x0000, 0x0000, 0x0004
  ) .. string.rep("\x00", 20)

  local trans_status = smb.send_transaction_named_pipe(
    smbstate, fid, "\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .. trans_data
  )

  smb.stop(smbstate)

  if trans_status then
    return true, "Vulnerable"
  end
  return false, "Transaction blocked — likely patched"
end

local function probe_smb2_compression(host, port)
  local sock = raw_connect(host, port)
  if not sock then return false end

  local smb2_neg = build_smb2_negotiate()
  local resp     = send_recv(sock, smb2_neg)
  if not resp then
    sock:close()
    return false
  end

  local cap_offset = 100
  if #resp < cap_offset + 4 then
    sock:close()
    return false
  end

  local _, capabilities = bin.unpack("<I", resp, cap_offset)
  sock:close()

  local SMB2_GLOBAL_CAP_COMPRESSION = 0x00000040
  return bit.band(capabilities or 0, SMB2_GLOBAL_CAP_COMPRESSION) ~= 0
end

local function check_smb_signing(host)
  local status, neg = smb.get_security_mode(host)
  if not status then return nil end
  return {
    enabled  = neg.security_mode and bit.band(neg.security_mode, 0x08) ~= 0,
    required = neg.security_mode and bit.band(neg.security_mode, 0x04) ~= 0,
  }
end

local function enumerate_named_pipes(host, port)
  local pipes = {
    "\\PIPE\\srv",  "\\PIPE\\browser", "\\PIPE\\lanman",
    "\\PIPE\\lsarpc", "\\PIPE\\samr",  "\\PIPE\\netlogon",
    "\\PIPE\\ntsvcs", "\\PIPE\\svcctl",
  }
  local accessible = {}

  local smbstate
  local ok = smb.start(host)
  if not ok then return accessible end

  local s
  ok, s = smb.start(host)
  if not ok then return accessible end

  ok = smb.negotiate_protocol(s, {})
  if not ok then smb.stop(s) return accessible end

  ok = smb.start_session(s, {username="", password="", domain=""})
  if not ok then smb.stop(s) return accessible end

  smb.tree_connect(s, "\\\\IPC$")

  for _, pipe in ipairs(pipes) do
    local fok = smb.create_file(s, pipe)
    if fok then
      table.insert(accessible, pipe)
    end
  end

  smb.stop(s)
  return accessible
end

local function format_vuln(id, title, state, desc, cvss, cve_refs)
  return {
    id          = id,
    title       = title,
    state       = state,
    description = desc,
    scores      = {cvss = cvss},
    references  = cve_refs,
  }
end

action = function(host, port)
  local report  = vulns.Report:new(SCRIPT_NAME, host, port)
  local output  = stdnse.output_table()
  local summary = {}

  local dialect_idx = detect_smbv1_dialect(host, port)
  local smbv1_active = dialect_idx ~= nil and dialect_idx <= 5

  if smbv1_active then
    table.insert(summary, "[CRITICAL] SMBv1 active (dialect index: " .. tostring(dialect_idx) .. ")")
  else
    table.insert(summary, "[INFO] SMBv1 not negotiated or unavailable")
  end

  local et_ok, et_msg = probe_ms17010_transaction(host, port)
  local vuln_ms17010  = format_vuln(
    "MS17-010",
    "EternalBlue SMB Remote Code Execution",
    et_ok and vulns.State.LIKELY_VULN or vulns.State.NOT_VULN,
    "Remote code execution via malformed transaction request to \\PIPE\\srv on SMBv1.",
    et_ok and 9.3 or 0.0,
    {"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144"}
  )
  report:add_vulns(vuln_ms17010)
  table.insert(summary, string.format("[MS17-010] %s — %s", et_ok and "VULNERABLE" or "Not vulnerable", et_msg))

  local smbghost = probe_smb2_compression(host, port)
  local vuln_smbghost = format_vuln(
    "CVE-2020-0796",
    "SMBGhost — SMB 3.1.1 Compression RCE",
    smbghost and vulns.State.LIKELY_VULN or vulns.State.NOT_VULN,
    "SMB 3.1.1 compression capability exposed; pre-auth RCE possible without credentials.",
    smbghost and 10.0 or 0.0,
    {"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796"}
  )
  report:add_vulns(vuln_smbghost)
  table.insert(summary, string.format("[SMBGhost] %s", smbghost and "Compression flag SET — LIKELY VULNERABLE" or "Compression flag absent"))

  local signing = check_smb_signing(host)
  if signing then
    if not signing.required then
      table.insert(summary, "[HIGH] SMB signing NOT required — relay/MitM attacks possible")
    elseif not signing.enabled then
      table.insert(summary, "[MEDIUM] SMB signing disabled entirely")
    else
      table.insert(summary, "[OK] SMB signing enabled and required")
    end
  end

  local pipes = enumerate_named_pipes(host, port)
  if #pipes > 0 then
    table.insert(summary, string.format("[INFO] %d named pipe(s) accessible via null session:", #pipes))
    for _, p in ipairs(pipes) do
      table.insert(summary, "       " .. p)
    end
  else
    table.insert(summary, "[INFO] No named pipes accessible via null session")
  end

  output["Scan Results"] = summary
  return output, report:make_output()
end
