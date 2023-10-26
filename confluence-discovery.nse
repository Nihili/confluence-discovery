local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs Atlassian Confluence discovery by checking for the existence of the X-Confluence-Request-Time HTTP header in HTTP response.
]]

---
--@output
--443/tcp open  https
--| confluence-discovery:
--|_  Confluence found at example.com:443/
--
--@args path The http path to use for the request. Default: <code>/</code>
--

author = "Karol Suski"

license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
	
	local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
	
	response = http.get(host, port, path)
	
	if not (response and response.status) then
		return stdnse.format_output(false, "Request failed.")
	end
	
	if(not (response.header['x-confluence-request-time'] == nil)) then
		return(stdnse.format_output(true, "Confluence found at " .. host.targetname .. ":" .. port.number .. path))
	end
	
	return stdnse.format_output(false, "No confluence header found.")
	
end
