local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Checks if a Docker Remote API instance is exposed without authentication.
]]

author = "MatrixTM26"
license = "Same as Nmap--See https://nmap.org"
categories = {"vuln", "discovery", "intrusive"}

portrule = shortport.portnumber(2375, "tcp")

action = function(HostData, PortData)
    local TargetPath = "/version"
    local HttpResponse = http.get(HostData, PortData, TargetPath)
    
    if not HttpResponse then
        return nil
    end
    
    local VulnTable = {
        title = "Unauthenticated Docker Remote API Exposure",
        state = vulns.STATE.NOT_VULN,
        description = string.format("Docker API is accessible without authentication on port %d", PortData.number),
        references = {
            'https://mitre.org'
        }
    }
    local ScanReport = vulns.Report:new(SCRIPT_NAME, HostData, PortData)

    if HttpResponse.status == 200 and HttpResponse.body then
        if string.match(HttpResponse.body, "ApiVersion") or string.match(HttpResponse.body, "Arch") or string.match(HttpResponse.body, "KernelVersion") then
            VulnTable.state = vulns.STATE.VULN
            VulnTable.exploit_results = string.format("Exposed Docker instance information:\n%s", HttpResponse.body)
        end
    end

    if VulnTable.state == vulns.STATE.VULN then
        return ScanReport:make_output(VulnTable)
    end
end
