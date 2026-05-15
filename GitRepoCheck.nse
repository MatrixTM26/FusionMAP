local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Checks if a web server accidentally exposes its internal .git repository directory.
]]

author = "CyberSecurity Researcher"
license = "Same as Nmap--See https://nmap.org"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

action = function(HostData, PortData)
    local TargetPath = "/.git/HEAD"
    local HttpResponse = http.get(HostData, PortData, TargetPath)
    
    if not HttpResponse then
        return nil
    end
    
    local VulnTable = {
        title = "Git Repository Exposure",
        state = vulns.STATE.NOT_VULN,
        description = string.format("Git directory exposed at http://%s:%d/.git/", HostData.targetname or HostData.ip, PortData.number),
        references = {
            'https://owasp.org'
        }
    }
    local ScanReport = vulns.Report:new(SCRIPT_NAME, HostData, PortData)

    if HttpResponse.status == 200 and HttpResponse.body then
        if string.match(HttpResponse.body, "ref: refs/") then
            VulnTable.state = vulns.STATE.VULN
            VulnTable.exploit_results = string.format("Successful match found in HEAD file:\n  %s", HttpResponse.body)
        end
    end

    if VulnTable.state == vulns.STATE.VULN then
        return ScanReport:make_output(VulnTable)
    end
end
