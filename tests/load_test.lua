-- WAF + Reverse Proxy Load Test Script
-- For use with wrk: wrk -t12 -c400 -d30s -s load_test.lua http://localhost:8080/

-- Load test scenarios for different endpoints
local paths = {
    "/",
    "/api/health",
    "/api/status",
    "/test",
    "/static/index.html"
}

-- Various HTTP methods to test
local methods = {"GET", "POST", "PUT"}

-- User agents to test bot detection
local user_agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.25.1"
}

-- Request counter
local counter = 0

-- Setup function called once per thread
setup = function(thread)
    thread:set("id", counter)
    counter = counter + 1
end

-- Request function called for each request
request = function()
    counter = counter + 1
    
    -- Select path, method, and user agent
    local path = paths[math.random(#paths)]
    local method = methods[math.random(#methods)]
    local user_agent = user_agents[math.random(#user_agents)]
    
    -- Build request headers
    local headers = {
        ["User-Agent"] = user_agent,
        ["Accept"] = "application/json, text/html",
        ["Connection"] = "keep-alive"
    }
    
    -- Add body for POST/PUT requests
    local body = nil
    if method == "POST" or method == "PUT" then
        headers["Content-Type"] = "application/json"
        body = '{"test": "data", "counter": ' .. counter .. '}'
    end
    
    -- Add some variation to simulate real traffic
    if counter % 10 == 0 then
        -- Simulate potential SQL injection attempt (should be blocked by WAF)
        path = path .. "?id=1' OR '1'='1"
    elseif counter % 15 == 0 then
        -- Simulate XSS attempt (should be blocked by WAF)
        path = path .. "?search=<script>alert('xss')</script>"
    end
    
    return wrk.format(method, path, headers, body)
end

-- Response function called for each response
response = function(status, headers, body)
    -- Track different response types
    if status >= 200 and status < 300 then
        -- Success
    elseif status >= 400 and status < 500 then
        -- Client error (expected for WAF blocks)
    elseif status >= 500 then
        -- Server error (unexpected)
        print("Server error: " .. status)
    end
end

-- Done function called when test completes
done = function(summary, latency, requests)
    print("Load test completed:")
    print("  Requests: " .. summary.requests)
    print("  Errors: " .. summary.errors.connect + summary.errors.read + summary.errors.write + summary.errors.status + summary.errors.timeout)
    print("  Duration: " .. summary.duration .. "ms")
    print("  Bytes read: " .. summary.bytes)
    print("")
    print("Latency distribution:")
    print("  50th percentile: " .. latency:percentile(50.0) .. "ms")
    print("  90th percentile: " .. latency:percentile(90.0) .. "ms")
    print("  99th percentile: " .. latency:percentile(99.0) .. "ms")
    print("  Max latency: " .. latency.max .. "ms")
end
