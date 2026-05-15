local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Checks if a web server accidentally exposes a sensitive .env configuration file.
]]

author = "MatrixTM26"
license = "Same as Nmap--See https://nmap.org"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

action = function(HostData, PortData)
    local TargetPath = "/.env"
    local HttpResponse = http.get(HostData, PortData, TargetPath)
    
    if not HttpResponse then
        return nil
    end
    
    local VulnTable = {
        title = "Sensitive Configuration File Exposure (.env)",
        state = vulns.STATE.NOT_VULN,
        description = string.format("File found at http://%s:%d%s", HostData.targetname or HostData.ip, PortData.number, TargetPath),
        references = {
            'https://owasp.org'
        }
    }
    local ScanReport = vulns.Report:new(SCRIPT_NAME, HostData, PortData)

    if HttpResponse.status == 200 and HttpResponse.body then
        if string.match(HttpResponse.body, "DB") or string.match(HttpResponse.body, "APP") or string.match(HttpResponse.body, "SECRET") then
            VulnTable.state = vulns.STATE.VULN
            local ProofOfConceptLines = {}
            for LineData in string.gmatch(HttpResponse.body, "[^\r\n]+") do
                if string.match(LineData, "DBHOST") or string.match(LineData, "APPENV") or string.match(LineData, "DBUSER") or string.match(LineData, "HOST") or string.match(LineData, "USER") then
                    table.insert(ProofOfConceptLines, "  " .. LineData)
                end
            end
            if #ProofOfConceptLines > 0 then
                VulnTable.exploit_results = "Exposed data found:\n" .. table.concat(ProofOfConceptLines, "\n")
            end
        end
    end

    if VulnTable.state == vulns.STATE.VULN then
        return ScanReport:make_output(VulnTable)
    end
end

