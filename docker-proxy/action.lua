-- HAProxy glue for policy.lua: builds the request description from the HAProxy fetches, answers the two questions
-- the policy may ask the daemon, and turns the decision into a reply. Nothing here decides anything.
--
-- `txn.pn_allow` is set as the very last statement of the action. haproxy.cfg denies every request that lacks it,
-- so a runtime error anywhere in here fails closed.

package.path = "/etc/postern-proxy/?.lua;" .. package.path
local policy = require("policy")

local SOCKET = os.getenv("POSTERN_DOCKER_SOCKET") or "/var/run/docker.sock"
-- Failure bound on one round trip to the local daemon, in seconds.
local DAEMON_TIMEOUT = 5

local cfg = policy.config_from_env(os.getenv)
core.Info("postern docker-proxy: instance=" .. tostring(cfg.instance) .. " image=" .. cfg.image .. " network=" .. cfg.network)

-- One HTTP/1.0 GET over the daemon socket, read to EOF. Returns the raw reply, or nil, err.
local function daemon_get(uri)
  local s = core.tcp()
  s:settimeout(DAEMON_TIMEOUT)
  local ok, err = s:connect("unix@" .. SOCKET)
  if not ok then return nil, "connect: " .. tostring(err) end
  local sent, serr = s:send("GET " .. uri .. " HTTP/1.0\r\nHost: docker\r\n\r\n")
  if not sent then
    s:close()
    return nil, "send: " .. tostring(serr)
  end
  local data, rerr = s:receive("*a")
  s:close()
  if not data then return nil, "receive: " .. tostring(rerr) end
  return data
end

local io_daemon = {
  version = function() return daemon_get("/version") end,
  -- docker's id filter is a prefix match; policy.lua only asks with a full 64-hex id.
  probe = function(id) return daemon_get("/containers/json?all=1&filters=%7B%22id%22%3A%5B%22" .. id .. "%22%5D%7D") end,
}

local function headers_of(txn)
  local out = {}
  for name, values in pairs(txn.http:req_get_headers()) do
    local list = {}
    for _, value in pairs(values) do list[#list + 1] = value end
    out[name] = list
  end
  return out
end

local function request_of(txn)
  return {
    method = txn.sf:method() or "",
    path = txn.sf:path() or "",
    query = txn.sf:query() or "",
    headers = headers_of(txn),
    body = txn.sf:req_body() or "",
    body_size = tonumber(txn.f:req_body_size()) or 0,
    body_len = tonumber(txn.f:req_body_len()) or 0,
  }
end

local function reply(txn, status, message)
  local r = txn:reply()
  r:set_status(status)
  r:add_header("Content-Type", "application/json")
  r:set_body('{"message":"' .. message:gsub("[^%w _%.:/=,%-]", "?") .. '"}\n')
  txn:done(r)
end

core.register_action("pn_filter", {"http-req"}, function(txn)
  local ok, allowed, status, reason = pcall(function() return policy.decide(request_of(txn), cfg, io_daemon) end)
  if not ok then
    core.Alert("postern docker-proxy: policy error: " .. tostring(allowed))
    return
  end
  if not allowed then
    core.Warning("postern docker-proxy: deny " .. tostring(status) .. ": " .. tostring(reason))
    reply(txn, status, "request denied by the postern docker-proxy: " .. tostring(reason))
    return
  end
  txn:set_var("txn.pn_allow", true)
end)
