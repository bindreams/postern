-- Tests for action.lua, the HAProxy glue: it is loaded here with a fake `core` and a fake daemon socket, and its two
-- registered actions are driven with fake transactions. Run from test_policy.lua (dofile), which hands over its
-- counting `eq` and the constants it shares.
--
-- What this pins that policy.lua's own tests cannot: the glue reads the request and the response status from the
-- right fetches, passes `txn.pn_path` from the request action to the response action, and a forwarded DELETE that
-- the daemon answers 2xx or 404 really makes the next request for that id probe the daemon again.

return function(eq, ctx)
  local ID, INSTANCE, IMAGE, NETWORK, API = ctx.ID, ctx.INSTANCE, ctx.IMAGE, ctx.NETWORK, ctx.API

  -- Fake daemon socket: answers GET /_ping and the by-id list probe, and counts probes.
  local probes = 0
  local function fake_tcp()
    local sock, request = {}, nil
    function sock:settimeout() end
    function sock:connect() return 1 end
    function sock:send(data) request = data; return #data end
    function sock:receive()
      if request:find("^GET /_ping ") then return ctx.ping_reply(API) end
      local id = request:match("^GET /containers/json%?[^ ]*%%22(%x+)%%22")
      if id then
        probes = probes + 1
        return ctx.owned_reply(id, INSTANCE)
      end
      return nil, "unexpected request"
    end
    function sock:close() end
    return sock
  end

  -- Fake transaction. `status` is what the daemon answered, for the response action.
  local function txn_of(method, path, query, status)
    local vars, replied = {}, nil
    local t = {vars = vars}
    t.sf = {
      method = function() return method end, path = function() return path end,
      query = function() return query or "" end, req_body = function() return "" end,
      status = function() return status end,
    }
    t.f = {req_body_size = function() return 0 end, req_body_len = function() return 0 end}
    t.http = {req_get_headers = function() return {host = {[0] = "docker"}} end}
    function t:set_var(name, value) vars[name] = value end
    function t:get_var(name) return vars[name] end
    function t:reply()
      local r = {headers = {}}
      function r:set_status(s) self.status = s end
      function r:add_header(k, val) self.headers[k] = val end
      function r:set_body(b) self.body = b end
      return r
    end
    function t:done(r) replied = r end
    function t:replied() return replied end
    return t
  end

  -- Load action.lua against the fakes. They stay installed (the glue looks `core` up at call time) until `restore`.
  local LEVELS = {"Info", "Warning", "Alert"}
  local real = {tcp = core.tcp, register_action = core.register_action, getenv = os.getenv}
  for _, level in ipairs(LEVELS) do real[level] = core[level] end
  local actions, logged = {}, {}
  local env = {
    SHADOWSOCKS_IMAGE = IMAGE, SHADOWSOCKS_NETWORK = NETWORK, INSTANCE_ID = INSTANCE,
    POSTERN_DOCKER_SOCKET = "/nonexistent",
  }
  local function restore()
    core.tcp, core.register_action, os.getenv = real.tcp, real.register_action, real.getenv
    for _, level in ipairs(LEVELS) do core[level] = real[level] end
  end
  local function load_action(overrides)
    core.tcp = fake_tcp
    core.register_action = function(name, _, fn) actions[name] = fn end
    for _, level in ipairs(LEVELS) do
      core[level] = function(msg) logged[#logged + 1] = level .. ": " .. msg end
    end
    os.getenv = function(name)
      if overrides and overrides[name] ~= nil then return overrides[name] or nil end
      return env[name]
    end
    local ok, err = pcall(dofile, "/pn/action.lua")
    os.getenv = real.getenv
    assert(ok, "action.lua failed to load: " .. tostring(err))
  end

  load_action()
  local filter, evict = actions.pn_filter, actions.pn_evict
  eq("action: both actions are registered", type(filter) == "function" and type(evict) == "function", true)

  local DEL_Q = "v=False&link=False&force=True"
  local function inspect() return txn_of("GET", "/v" .. API .. "/containers/" .. ID .. "/json") end
  local function delete() return txn_of("DELETE", "/v" .. API .. "/containers/" .. ID, DEL_Q, 204) end

  local t = inspect()
  filter(t)
  eq("action: an owned inspect is allowed", t.vars["txn.pn_allow"], true)
  eq("action: the request path is kept for the response action", t.vars["txn.pn_path"], "/v" .. API .. "/containers/" .. ID .. "/json")
  eq("action: the first request probes", probes, 1)

  filter(inspect())
  eq("action: a vouched id is not probed again", probes, 1)

  -- A forwarded DELETE answered 2xx evicts the id: the next request for it probes again.
  local d = delete()
  filter(d)
  eq("action: the delete is allowed", d.vars["txn.pn_allow"], true)
  eq("action: the delete of a vouched id does not probe", probes, 1)
  evict(d)
  filter(inspect())
  eq("action: after a delete answered 204 the id is probed again", probes, 2)

  -- 404 evicts as well; 409 (removal in progress) does not.
  d = delete()
  filter(d)
  d.sf.status = function() return 409 end
  evict(d)
  filter(inspect())
  eq("action: a delete answered 409 keeps the id vouched", probes, 2)
  d.sf.status = function() return 404 end
  evict(d)
  filter(inspect())
  eq("action: a delete answered 404 evicts", probes, 3)

  -- A response for a request that never passed the request action (no pn_path) must not raise or evict.
  local stray = txn_of("DELETE", "", "", 204)
  evict(stray)
  filter(inspect())
  eq("action: a response without a recorded path evicts nothing", probes, 3)

  -- Denial: a reply, and no `pn_allow`, which is what haproxy.cfg's fail-closed rule keys on.
  local denied = txn_of("GET", "/v" .. API .. "/images/json")
  filter(denied)
  eq("action: a denied request does not set pn_allow", denied.vars["txn.pn_allow"], nil)
  local r = denied:replied()
  eq("action: a denied request is answered 403", r and r.status, 403)
  eq("action: the denial names the proxy", r and r.body:find("postern docker-proxy", 1, true) ~= nil, true)

  -- A runtime error in the policy path fails closed: no pn_allow, an alert, no reply to fall back on.
  local broken = txn_of("GET", "/v" .. API .. "/containers/" .. ID .. "/json")
  broken.sf.method = function() error("boom") end
  logged = {}
  filter(broken)
  eq("action: an error does not set pn_allow", broken.vars["txn.pn_allow"], nil)
  eq("action: an error is logged as an alert", #logged == 1 and logged[1]:find("^Alert: postern docker%-proxy: policy error") ~= nil, true)

  -- An unusable instance id is reported when the glue loads, naming the raw values and the grammar.
  logged = {}
  load_action({INSTANCE_ID = "bad:id", COMPOSE_PROJECT_NAME = false})
  local warned = false
  for _, line in ipairs(logged) do
    if line:find("^Warning:") and line:find("bad:id", 1, true) and line:find("A-Za-z0-9", 1, true) then warned = true end
  end
  eq("action: an unusable instance id is warned about at load", warned, true)
  logged = {}
  load_action()
  for _, line in ipairs(logged) do eq("action: a usable instance id is not warned about", line:find("^Warning:"), nil) end
  restore()
end
