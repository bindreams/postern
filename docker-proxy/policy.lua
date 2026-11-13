-- The docker-proxy allow-list: a pure decision function over one request.
--
-- Everything here is plain Lua; the HAProxy API is touched only by action.lua. The only external effects
-- are the two functions in `io`, both of which return the raw bytes of a dockerd reply (or nil, err):
--   io.version()  -> reply to an unversioned GET /version
--   io.probe(id)  -> reply to GET /containers/json?all=1&filters={"id":["<id>"]}
-- Optional, so the glue can cache: io.version_fresh() (a read that bypasses the version cache, asked once when a
-- request's version differs from the cached one), io.owned(id) (true if this id was already vouched for) and
-- io.remember(id) (called after a probe vouches for it). A cache can only skip a question whose answer cannot change.
-- Default deny: a request is allowed only if it matches one route exactly. See docs/development/architecture.md.
--
-- decide(req, cfg, io) returns `true`, or `false, status, reason` (403, or 404 for a container id the daemon
-- does not know, so docker-py raises NotFound exactly as it would against dockerd).

local M = {}

-- What the reconciler creates ss-* containers with. reconciler.py (SS_MEMORY_BYTES, SS_PIDS_LIMIT, SS_TMPFS)
-- repeats these three; tests/test_compose_docker_proxy.py pins the copies equal.
M.SS_MEMORY_BYTES = 536870912
M.SS_PIDS_LIMIT = 1024
M.SS_TMPFS = {["/tmp"] = "", ["/home/nonroot/.cache"] = "exec"}

M.MAX_BODY = 8192
local MAX_REPLY = 1048576

M.NULL = setmetatable({}, {__tostring = function() return "null" end})
local ARR = {}
local OBJ = {}

-- JSON ==============================================================================================================
-- One parser, two modes.
--   "request": the subset docker-py emits. Printable ASCII only, no backslash, no duplicate keys, integers only,
--              spaces as the only whitespace, size-capped. This removes every difference between this parser and
--              dockerd's Go decoder (escapes, unicode, number forms) for any body that is accepted.
--   "reply":   general compact JSON as dockerd emits it. Escapes and UTF-8 pass through as opaque string bytes
--              (a label value written with an escape never equals the plain string it is compared with), nesting
--              is allowed up to a fixed depth, duplicate keys and trailing data are rejected, and no whitespace
--              is accepted outside strings, except after the value (Docker Engine ends its bodies with a newline).
local function parse_json(s, mode)
  local request = mode == "request"
  if request then
    if #s > M.MAX_BODY then return nil, "body too large" end
    if s:find("[^\32-\126]") then return nil, "non-printable-ascii byte" end
    if s:find("\\", 1, true) then return nil, "backslash" end
  elseif #s > MAX_REPLY then
    return nil, "reply too large"
  end
  local max_depth = request and 8 or 32
  local i = 1
  local value

  local function ws()
    if request then i = s:find("[^ ]", i) or (#s + 1) end
  end

  local function str()
    if request then
      local j = s:find('"', i + 1, true)
      if not j then error("unterminated string") end
      local v = s:sub(i + 1, j - 1)
      i = j + 1
      return v
    end
    local j = i + 1
    while true do
      local c = s:byte(j)
      if not c then error("unterminated string") end
      if c == 34 then break end
      if c == 92 then
        local e = s:sub(j + 1, j + 1)
        if e:find('^["\\/bfnrt]$') then
          j = j + 2
        elseif e == "u" and s:sub(j + 2, j + 5):find("^%x%x%x%x$") then
          j = j + 6
        else
          error("bad escape")
        end
      elseif c < 32 then
        error("control byte in string")
      else
        j = j + 1
      end
    end
    local v = s:sub(i + 1, j - 1)
    i = j + 1
    return v
  end

  local function obj(depth)
    local t = setmetatable({}, OBJ)
    i = i + 1
    ws()
    if s:sub(i, i) == "}" then
      i = i + 1
      return t
    end
    while true do
      ws()
      if s:sub(i, i) ~= '"' then error("key expected") end
      local k = str()
      ws()
      if s:sub(i, i) ~= ":" then error("colon expected") end
      i = i + 1
      ws()
      if t[k] ~= nil then error("duplicate key " .. k) end
      t[k] = value(depth + 1)
      ws()
      local c = s:sub(i, i)
      i = i + 1
      if c == "}" then return t elseif c ~= "," then error("comma expected") end
    end
  end

  local function arr(depth)
    local t = setmetatable({}, ARR)
    i = i + 1
    ws()
    if s:sub(i, i) == "]" then
      i = i + 1
      return t
    end
    while true do
      ws()
      t[#t + 1] = value(depth + 1)
      ws()
      local c = s:sub(i, i)
      i = i + 1
      if c == "]" then return t elseif c ~= "," then error("comma expected") end
    end
  end

  function value(depth)
    if depth > max_depth then error("nesting too deep") end
    ws()
    local c = s:sub(i, i)
    if c == "{" then
      return obj(depth)
    elseif c == "[" then
      return arr(depth)
    elseif c == '"' then
      return str()
    elseif s:sub(i, i + 3) == "true" then
      i = i + 4
      return true
    elseif s:sub(i, i + 4) == "false" then
      i = i + 5
      return false
    elseif s:sub(i, i + 3) == "null" then
      i = i + 4
      return M.NULL
    end
    local num = s:match("^-?0", i) or s:match("^-?[1-9]%d*", i)
    if not num then error("bad value at " .. i) end
    if not request then
      -- dockerd's output may carry fractions and exponents
      num = num .. (s:match("^%.%d+", i + #num) or "")
      num = num .. (s:match("^[eE][+-]?%d+", i + #num) or "")
    end
    i = i + #num
    return tonumber(num)
  end

  local ok, v = pcall(function()
    local r = value(1)
    if request then ws() else i = s:find("[^ \t\r\n]", i) or (#s + 1) end
    if i <= #s then error("trailing data") end
    return r
  end)
  if not ok then return nil, (tostring(v):gsub("^[^:]*:%d+: ", "")) end
  return v
end
M.parse_json = parse_json

local function is_obj(t) return type(t) == "table" and getmetatable(t) == OBJ end
local function is_arr(t) return type(t) == "table" and getmetatable(t) == ARR end

local function keys_within(t, allowed)
  for k in pairs(t) do
    if not allowed[k] then return false, "key not allowed: " .. tostring(k) end
  end
  return true
end

-- True iff `t` is a JSON object with exactly the keys of `expected`, each equal to the expected scalar.
local function obj_equals(t, expected)
  if not is_obj(t) then return false end
  for k, v in pairs(expected) do
    if t[k] ~= v then return false end
  end
  for k in pairs(t) do
    if expected[k] == nil then return false end
  end
  return true
end

local function is_string_list(t, expected)
  if not is_arr(t) or #t ~= #expected then return false end
  for n, v in ipairs(expected) do
    if t[n] ~= v then return false end
  end
  return true
end

-- HTTP replies from dockerd ============================================================================================
-- Strict: anything unexpected is an error, and every caller treats an error as a deny.
local function dechunk(body)
  local out, pos = {}, 1
  while true do
    local hex, after = body:match("^(%x+)\r\n()", pos)
    if not hex or #hex > 8 then return nil, "bad chunk size" end
    local n = tonumber(hex, 16)
    pos = after
    if n == 0 then
      if body:sub(pos) ~= "\r\n" then return nil, "bad chunked terminator" end
      return table.concat(out)
    end
    if #body < pos + n + 1 or body:sub(pos + n, pos + n + 1) ~= "\r\n" then return nil, "bad chunk" end
    out[#out + 1] = body:sub(pos, pos + n - 1)
    pos = pos + n + 2
  end
end

-- raw reply bytes -> status (number), body (string) | nil, err
local function parse_http_reply(raw)
  if type(raw) ~= "string" then return nil, "no reply" end
  local head_end = raw:find("\r\n\r\n", 1, true)
  if not head_end then return nil, "no header terminator" end
  local head, body = raw:sub(1, head_end - 1), raw:sub(head_end + 4)
  local status = head:match("^HTTP/1%.[01] (%d%d%d) ")
  if not status then return nil, "bad status line" end
  local chunked, content_length
  for line in head:gmatch("\r\n([^\r\n]*)") do
    local name, val = line:match("^([^:]+):[ \t]*(.-)[ \t]*$")
    if not name then return nil, "bad header line" end
    name = name:lower()
    if name == "transfer-encoding" then
      if chunked or val:lower() ~= "chunked" then return nil, "unsupported transfer-encoding" end
      chunked = true
    elseif name == "content-length" then
      if content_length or not val:find("^%d+$") then return nil, "bad content-length" end
      content_length = tonumber(val)
    end
  end
  if chunked then
    if content_length then return nil, "chunked with content-length" end
    local err
    body, err = dechunk(body)
    if not body then return nil, err end
  elseif content_length and content_length ~= #body then
    return nil, "truncated body"
  end
  return tonumber(status), body
end
M.parse_http_reply = parse_http_reply

-- reply to GET /version -> "1.56" | nil, err
local function api_version(raw)
  local status, body = parse_http_reply(raw)
  if status ~= 200 then return nil, "version read failed" end
  local v = parse_json(body, "reply")
  if not is_obj(v) or type(v.ApiVersion) ~= "string" or not v.ApiVersion:find("^%d+%.%d+$") then
    return nil, "version reply unusable"
  end
  return v.ApiVersion
end

M.api_version = api_version

local function owned_labels(labels, cfg)
  return is_obj(labels) and labels["postern.managed"] == "true" and labels["postern.instance"] == cfg.instance
end

-- Ownership probe, reply side. Returns "owned" | "gone" | nil, err.
--   "gone"  : dockerd lists no container with this id
--   "owned" : it lists exactly this id, carrying this deployment's two labels
--   nil     : anything else (read failure, odd reply, other labels, several entries)
local function probe_outcome(raw, id, cfg)
  local status, body = parse_http_reply(raw)
  if status ~= 200 then return nil, "probe failed" end
  local list = parse_json(body, "reply")
  if not is_arr(list) then return nil, "probe reply is not a list" end
  if #list == 0 then return "gone" end
  if #list ~= 1 then return nil, "not owned" end
  local entry = list[1]
  if is_obj(entry) and entry.Id == id and owned_labels(entry.Labels, cfg) then return "owned" end
  return nil, "not owned"
end
M.probe_outcome = probe_outcome

-- Create body ==========================================================================================================
local TOP_FALSE = {"Tty", "OpenStdin", "StdinOnce", "AttachStdin", "AttachStdout", "AttachStderr", "NetworkDisabled"}
local TOP_KEYS = {Env = 1, Image = 1, HostConfig = 1, NetworkingConfig = 1, Labels = 1}
for _, k in ipairs(TOP_FALSE) do TOP_KEYS[k] = 1 end
local HOST_KEYS = {
  NetworkMode = 1, RestartPolicy = 1, LogConfig = 1, Init = 1, CapDrop = 1, SecurityOpt = 1, ReadonlyRootfs = 1,
  Memory = 1, PidsLimit = 1, Tmpfs = 1,
}

local function create_body_ok(body, cfg)
  local b, err = parse_json(body, "request")
  if b == nil then return false, "create body: " .. err end
  if not is_obj(b) then return false, "create body is not an object" end
  local ok, why = keys_within(b, TOP_KEYS)
  if not ok then return false, why end
  for _, k in ipairs(TOP_FALSE) do
    if b[k] ~= nil and b[k] ~= false then return false, k .. " must be false" end
  end
  if b.Image ~= cfg.image then return false, "Image must equal the configured image" end
  if not (is_arr(b.Env) and #b.Env == 1 and type(b.Env[1]) == "string" and b.Env[1]:find("^SS_CONFIG=[A-Za-z0-9+/=]+$")) then
    return false, "Env must be exactly one SS_CONFIG"
  end
  if not obj_equals(b.Labels, {["postern.managed"] = "true", ["postern.instance"] = cfg.instance}) then
    return false, "Labels must be exactly the two postern labels"
  end
  local h = b.HostConfig
  if not is_obj(h) then return false, "HostConfig missing" end
  ok, why = keys_within(h, HOST_KEYS)
  if not ok then return false, "HostConfig " .. why end
  if h.NetworkMode ~= cfg.network then return false, "NetworkMode must be the shadowsocks network" end
  if not obj_equals(h.RestartPolicy, {Name = "unless-stopped"}) then return false, "RestartPolicy" end
  local log = h.LogConfig
  if not (is_obj(log) and log.Type == "none" and is_obj(log.Config) and next(log.Config) == nil) then
    return false, "LogConfig"
  end
  for k in pairs(log) do
    if k ~= "Type" and k ~= "Config" then return false, "LogConfig" end
  end
  if h.Init ~= true then return false, "Init must be true" end
  if not is_string_list(h.CapDrop, {"ALL"}) then return false, "CapDrop must be [ALL]" end
  if not is_string_list(h.SecurityOpt, {"no-new-privileges:true"}) then return false, "SecurityOpt" end
  if h.ReadonlyRootfs ~= true then return false, "ReadonlyRootfs must be true" end
  if h.Memory ~= M.SS_MEMORY_BYTES then return false, "Memory" end
  if h.PidsLimit ~= M.SS_PIDS_LIMIT then return false, "PidsLimit" end
  if not obj_equals(h.Tmpfs, M.SS_TMPFS) then return false, "Tmpfs" end
  if b.NetworkingConfig ~= nil then
    local nc = b.NetworkingConfig
    if not (is_obj(nc) and nc[cfg.network] == M.NULL) then return false, "NetworkingConfig" end
    for k in pairs(nc) do
      if k ~= cfg.network then return false, "NetworkingConfig" end
    end
  end
  return true
end
M.create_body_ok = create_body_ok

-- Requests =============================================================================================================
local function pct_encode(s, keep)
  return (s:gsub("[^" .. keep .. "]", function(c) return string.format("%%%02X", c:byte()) end))
end

-- docker-py builds a path from an unquoted name with urllib.parse.quote(name, safe="/:").
local function quote_path(s) return pct_encode(s, "%w_%.%-~/:") end

-- "a=1&b=2" -> {a="1", b="2"} | nil, err. Values are percent-decoded; a duplicate key, a key that is not
-- lower-case letters or an underscore, or a malformed escape is an error.
local function parse_query(q)
  local out = {}
  if q == nil or q == "" then return out end
  for pair in (q .. "&"):gmatch("([^&]*)&") do
    local k, v = pair:match("^([a-z_]+)=(.*)$")
    if not k then return nil, "malformed query" end
    if out[k] ~= nil then return nil, "duplicate query key " .. k end
    if v:find("%%[^%x]") or v:find("%%%x[^%x]") or v:find("%%%x?$") then return nil, "malformed percent-escape" end
    out[k] = (v:gsub("+", " "):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
  end
  return out
end

-- The query must contain only keys of `want` (key -> exact value); each key is optional.
local function query_within(q, want)
  for k, v in pairs(q) do
    if want[k] == nil or want[k] ~= v then return false, "query parameter not allowed: " .. k end
  end
  return true
end

local function list_filters_ok(filters, cfg)
  local f = parse_json(filters, "request")
  if not is_obj(f) then return false, "filters" end
  if f.label ~= nil then
    if not cfg.instance then return false, "no instance id" end
    local want = {"postern.managed=true", "postern.instance=" .. cfg.instance}
    if next(f, "label") ~= nil or next(f) ~= "label" then return false, "filters" end
    if not is_string_list(f.label, want) then return false, "label filter" end
    return true
  end
  if f.name ~= nil then
    if next(f, "name") ~= nil or next(f) ~= "name" then return false, "filters" end
    if is_arr(f.name) and #f.name == 1 and type(f.name[1]) == "string" and f.name[1]:find("^%^/ss%-[0-9a-f]+%$$")
       and #f.name[1] == 30 then
      return true
    end
    return false, "name filter"
  end
  return false, "filters"
end

local function count(headers, name)
  local l = headers[name]
  return l and #l or 0
end

local function deny(reason) return false, 403, reason end

-- -> "1.56" | nil, why
local function read_version(fetch)
  local ok, raw, err = pcall(fetch)
  if not ok then return nil, raw end
  local version, why = api_version(raw)
  if not version then return nil, err or why end
  return version
end

local function decide(req, cfg, io)
  local headers = req.headers or {}
  for _, h in ipairs({"transfer-encoding", "upgrade", "expect"}) do
    if count(headers, h) > 0 then return deny("header not allowed: " .. h) end
  end
  if count(headers, "content-length") > 1 then return deny("more than one Content-Length") end

  local method, path = req.method, req.path
  local q, qerr = parse_query(req.query)
  if not q then return deny(qerr) end

  -- Version prefix: must equal the daemon's current ApiVersion.
  local ver, rest = path:match("^/v(%d+%.%d+)(/.*)$")
  if ver then
    local current, why = read_version(io.version)
    -- io.version may answer from a cache; a request that differs from it gets one fresh read before it is denied.
    if current and ver ~= current and io.version_fresh then current, why = read_version(io.version_fresh) end
    if not current then return deny("API version could not be read from the daemon (" .. tostring(why) .. ")") end
    if ver ~= current then return deny("API version " .. ver .. " is not the daemon's " .. current) end
    path = rest
  elseif path ~= "/_ping" and path ~= "/version" then
    return deny("unversioned path")
  end

  local create = method == "POST" and path == "/containers/create"
  if not create and (req.body_size or 0) ~= 0 then return deny("request body not allowed") end
  local function no_query()
    if next(q) ~= nil then return deny("query not allowed") end
    return true
  end

  if method == "GET" and (path == "/_ping" or path == "/version") then
    return no_query()
  end
  if method == "GET" and (cfg.image or "") ~= "" and path == "/images/" .. quote_path(cfg.image) .. "/json" then
    return no_query()
  end
  if method == "GET" and (cfg.network or "") ~= "" and path == "/networks/" .. quote_path(cfg.network) then
    return no_query()
  end

  if method == "GET" and path == "/containers/json" then
    local ok, why = query_within(q, {limit = "-1", all = "1", size = "0", trunc_cmd = "0", filters = q.filters})
    if not ok then return deny(why) end
    if not q.filters then return deny("unscoped container list") end
    ok, why = list_filters_ok(q.filters, cfg)
    if not ok then return deny(why) end
    return true
  end

  if create then
    local ok, why = query_within(q, {name = q.name})
    if not ok then return deny(why) end
    if not (q.name and #q.name == 27 and q.name:find("^ss%-[0-9a-f]+$")) then return deny("container name") end
    if count(headers, "content-length") ~= 1 then return deny("create needs exactly one Content-Length") end
    local ct = headers["content-type"]
    if not (ct and #ct == 1 and ct[1] == "application/json") then return deny("Content-Type must be application/json") end
    local body = req.body or ""
    if req.body_size ~= #body or req.body_len ~= #body or #body > M.MAX_BODY then
      return deny("create body not fully buffered or too large")
    end
    if not cfg.instance then return deny("no instance id") end
    local body_ok, body_why = create_body_ok(body, cfg)
    if not body_ok then return deny(body_why) end
    return true
  end

  -- Routes addressed by container id: allowed only after the daemon vouches for the id.
  local id, tail = path:match("^/containers/([0-9a-f]+)(.*)$")
  if id then
    local want
    if method == "GET" and tail == "/json" then
      want = {}
    elseif method == "POST" and tail == "/start" then
      want = {}
    elseif method == "POST" and tail == "/stop" then
      want = {t = "10"}
    elseif method == "DELETE" and tail == "" then
      want = {v = "False", link = "False", force = "True"}
    end
    if want and #id == 64 then
      local ok, why = query_within(q, want)
      if not ok then return deny(why) end
      if not cfg.instance then return deny("no instance id") end
      -- An id the daemon already vouched for stays vouched for: ids are never reused and labels are immutable.
      if io.owned then
        local kok, known = pcall(io.owned, id)
        if kok and known == true then return true end
      end
      local pok, raw, err = pcall(io.probe, id)
      local outcome, perr = nil, "probe failed (" .. tostring(pok and err or raw) .. ")"
      if pok and raw then outcome, perr = probe_outcome(raw, id, cfg) end
      if outcome == "owned" then
        if io.remember then pcall(io.remember, id) end
        return true
      end
      if outcome == "gone" then return false, 404, "No such container: " .. id end
      return deny(perr)
    end
  end

  return deny("route not allowed")
end
M.decide = decide

-- Config from the environment, mirroring reconciler.resolve_instance_id (stripped INSTANCE_ID override, else
-- stripped COMPOSE_PROJECT_NAME, else none). The instance id is pasted into a daemon filter, so it must be
-- harmless there.
local function strip(s) return (s or ""):match("^%s*(.-)%s*$") end
function M.config_from_env(getenv)
  local instance = strip(getenv("INSTANCE_ID"))
  if instance == "" then instance = strip(getenv("COMPOSE_PROJECT_NAME")) end
  if instance == "" or not instance:find("^[A-Za-z0-9][A-Za-z0-9_.-]*$") or #instance > 63 then instance = nil end
  return {instance = instance, image = getenv("SHADOWSOCKS_IMAGE") or "", network = getenv("SHADOWSOCKS_NETWORK") or ""}
end

return M
