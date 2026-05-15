local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Checks for the exposure of common sensitive files including admin panels, database dumps, and source backups.
]]

author = "CyberSecurity Researcher"
license = "Same as Nmap--See https://nmap.org"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

action = function(HostData, PortData)
    local TargetPaths = {"/admin.php", "/db.sql", "/backup.zip", "/dump.sql", "/config.bak"}
    local FoundFiles = {}
    
    local VulnTable = {
        title = "Sensitive File Exposure Detected",
        state = vulns.STATE.NOT_VULN,
        description = "One or more sensitive files or administrative portals were found accessible to the public.",
        references = {
            'https://owasp.org'
        }
    }
    local ScanReport = vulns.Report:new(SCRIPT_NAME, HostData, PortData)

    for PathIndex, PathValue in ipairs(TargetPaths) do
        local HttpResponse = http.get(HostData, PortData, PathValue)
        if HttpResponse and HttpResponse.status == 200 and HttpResponse.body then
            local IsValidMatch = false
            if PathValue == "/admin.php" and (string.match(HttpResponse.body, "login") or string.match(HttpResponse.body, "password") or string.match(HttpResponse.body, "username")) then
                IsValidMatch = true
            elseif (PathValue == "/db.sql" or PathValue == "/dump.sql") and (string.match(HttpResponse.body, "INSERT INTO") or string.match(HttpResponse.body, "CREATE TABLE")) then
                IsValidMatch = true
            elseif PathValue == "/backup.zip" and string.len(HttpResponse.body) > 0 then
                IsValidMatch = true
            elseif PathValue == "/config.bak" and string.len(HttpResponse.body) > 0 then
                IsValidMatch = true
            end
            if IsValidMatch then
                table.insert(FoundFiles, string.format("  Exposed: http://%s:%d%s", HostData.targetname or HostData.ip, PortData.number, PathValue))
            end
        end
    end

    if #FoundFiles > 0 then
        VulnTable.state = vulns.STATE.VULN
        VulnTable.exploit_results = "Accessible files listed below:\n" .. table.concat(FoundFiles, "\n")
        return ScanReport:make_output(VulnTable)
    end
end
