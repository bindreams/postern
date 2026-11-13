-- Unit tests for policy.lua, run inside the pinned HAProxy (the Lua build production uses). See haproxy.test.cfg.
--
-- Inputs, both provided by portal/tests/test_docker_proxy_policy.py:
--   stdin            the requests the real reconciler sends (docker-py 7.1.0 against a recording fake daemon):
--                    name TAB method TAB uri TAB content-type TAB body, one request per line.
--   TEST_* env       the Settings values the reconciler ran with (image, network, instance, API version).
-- tests/fixtures.lua holds raw dockerd replies recorded from daemon 29.9.3 (API 1.56): an HTTP/1.0 and an
-- HTTP/1.1 form of each; the CRLFs are part of what is tested.
--
-- Every negative case is differential: the unmodified baseline is accepted in the same run (see "baseline" below).

package.path = "/pn/?.lua;" .. package.path
local P = require("policy")

local IMAGE = os.getenv("TEST_IMAGE")
local NETWORK = os.getenv("TEST_NETWORK")
local INSTANCE = os.getenv("TEST_INSTANCE")
local API = os.getenv("TEST_API_VERSION")
local TOKEN = string.rep("a1", 12)
local ID = string.rep("c", 64)
local CFG = {image = IMAGE, network = NETWORK, instance = INSTANCE}

local FIXTURES = dofile("/pn/tests/fixtures.lua")
local function fixture(name) return assert(FIXTURES[name], name) end

-- Fakes ---------------------------------------------------------------------------------------------------------------
local function owned_reply(id, instance)
  local body = '[{"Id":"' .. id .. '","Names":["/x"],"Labels":{"postern.instance":"' .. instance
    .. '","postern.managed":"true"},"State":"running"}]'
  return "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" .. body
end
local VERSION_REPLY = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ApiVersion\":\"" .. API .. "\",\"Version\":\"29.9.3\"}"

local function fake_io(over)
  over = over or {}
  return {
    version = over.version or function() return VERSION_REPLY end,
    probe = over.probe or function(id) return owned_reply(id, INSTANCE) end,
  }
end

local function pct(s, keep)
  return (s:gsub("[^" .. keep .. "]", function(c) return c == " " and "+" or string.format("%%%02X", c:byte()) end))
end
local function enc(s) return pct(s, "%w_%.%-~") end
local function filters(json) return "filters=" .. enc(json) end

local function req(t)
  local body = t.body or ""
  return {
    method = t.method or "GET", path = t.path, query = t.query or "", headers = t.headers or {}, body = body,
    body_size = t.body_size or #body, body_len = t.body_len or #body,
  }
end
local function v(path) return "/v" .. API .. path end

-- Runner --------------------------------------------------------------------------------------------------------------
local fails, total = 0, 0
local function check(name, want, r, cfg, io)
  total = total + 1
  local ok, status, reason = P.decide(r, cfg or CFG, io or fake_io())
  local got = ok and "allow" or status
  if got ~= want then
    fails = fails + 1
    print(string.format("FAIL %-60s want %s got %s (%s)", name, tostring(want), tostring(got), tostring(reason)))
  elseif os.getenv("TEST_VERBOSE") then
    print(string.format("ok   %-60s %s %s", name, tostring(got), tostring(reason or "")))
  end
end
local function eq(name, got, want)
  total = total + 1
  if got ~= want then
    fails = fails + 1
    print(string.format("FAIL %-60s want %s got %s", name, tostring(want), tostring(got)))
  end
end

-- Wire requests the reconciler sends -----------------------------------------------------------------------------------
local wire, create_wire = {}, nil
for line in io.stdin:lines() do
  local name, method, uri, ctype, body = line:match("^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t(.*)$")
  assert(name, "bad wire line: " .. line)
  local path, query = uri:match("^([^?]*)%??(.*)$")
  local headers = {}
  if ctype ~= "" then headers["content-type"] = {ctype} end
  if body ~= "" then headers["content-length"] = {tostring(#body)} end
  local r = req({method = method, path = path, query = query, headers = headers, body = body})
  wire[#wire + 1] = {name = name, req = r}
  if method == "POST" and path:find("/containers/create$") then create_wire = r end
end
assert(#wire > 0 and create_wire, "wire.tsv has no create request")

for _, w in ipairs(wire) do check("wire: " .. w.name, "allow", w.req) end

-- Positives: every route, built by hand (the wire cases above cover what docker-py really sends) --------------------
local LIST_Q = "limit=-1&all=1&size=0&trunc_cmd=0&"
local LABEL_FILTER = '{"label": ["postern.managed=true", "postern.instance=' .. INSTANCE .. '"]}'
local NAME_FILTER = '{"name": ["^/ss-' .. TOKEN .. '$"]}'
check("ping unversioned", "allow", req{path = "/_ping"})
check("ping versioned", "allow", req{path = v("/_ping")})
check("version unversioned", "allow", req{path = "/version"})
check("image inspect", "allow", req{path = v("/images/" .. pct(IMAGE, "%w_%.%-~/:") .. "/json")})
check("network inspect", "allow", req{path = v("/networks/" .. pct(NETWORK, "%w_%.%-~/:"))})
check("list, this deployment's labels", "allow", req{path = v("/containers/json"), query = LIST_Q .. filters(LABEL_FILTER)})
check("list, by name", "allow", req{path = v("/containers/json"), query = LIST_Q .. filters(NAME_FILTER)})
check("inspect owned id", "allow", req{path = v("/containers/" .. ID .. "/json")})
check("start owned id", "allow", req{method = "POST", path = v("/containers/" .. ID .. "/start")})
check("stop owned id", "allow", req{method = "POST", path = v("/containers/" .. ID .. "/stop"), query = "t=10"})
check("delete owned id", "allow", req{method = "DELETE", path = v("/containers/" .. ID), query = "v=False&link=False&force=True"})

-- Routes that must stay denied (default deny: none of them is named in the policy) -------------------------------------
local denied = {
  {"GET", "/images/json"}, {"POST", "/images/create"}, {"POST", "/images/" .. IMAGE .. "/tag"}, {"POST", "/build"},
  {"POST", "/images/load"}, {"POST", "/commit"}, {"POST", "/images/" .. IMAGE .. "/push"},
  {"DELETE", "/images/" .. IMAGE}, {"POST", "/images/prune"}, {"GET", "/images/" .. IMAGE .. "/get"},
  {"GET", "/images/search"}, {"GET", "/images/" .. IMAGE .. "/history"}, {"POST", "/images/" .. IMAGE .. "/json"},
  {"GET", "/images/" .. IMAGE .. "/json/extra"},
  {"POST", "/containers/" .. ID .. "/update"}, {"POST", "/containers/" .. ID .. "/rename"},
  {"GET", "/containers/" .. ID .. "/archive"}, {"PUT", "/containers/" .. ID .. "/archive"},
  {"POST", "/containers/" .. ID .. "/attach"}, {"POST", "/containers/" .. ID .. "/exec"},
  {"GET", "/containers/" .. ID .. "/export"}, {"GET", "/containers/" .. ID .. "/changes"},
  {"GET", "/containers/" .. ID .. "/logs"}, {"GET", "/containers/" .. ID .. "/top"},
  {"POST", "/containers/" .. ID .. "/kill"}, {"POST", "/containers/" .. ID .. "/restart"},
  {"POST", "/containers/" .. ID .. "/pause"}, {"POST", "/containers/" .. ID .. "/unpause"},
  {"POST", "/containers/" .. ID .. "/wait"}, {"GET", "/containers/" .. ID .. "/stats"},
  {"POST", "/containers/" .. ID .. "/resize"}, {"POST", "/containers/prune"},
  {"POST", "/containers/" .. ID .. "/json"}, {"GET", "/containers/" .. ID .. "/start"},
  {"GET", "/containers/" .. ID .. "/stop"}, {"GET", "/containers/" .. ID}, {"PUT", "/containers/" .. ID},
  {"POST", "/containers/json"}, {"GET", "/containers/create"},
  {"POST", "/networks/create"}, {"POST", "/networks/" .. NETWORK .. "/connect"},
  {"POST", "/networks/" .. NETWORK .. "/disconnect"}, {"POST", "/networks/prune"}, {"DELETE", "/networks/" .. NETWORK},
  {"GET", "/networks"}, {"GET", "/networks/other"}, {"GET", "/volumes"}, {"POST", "/volumes/create"},
  {"GET", "/plugins"}, {"GET", "/swarm"}, {"GET", "/services"}, {"GET", "/secrets"}, {"GET", "/configs"},
  {"POST", "/session"}, {"POST", "/grpc"}, {"GET", "/events"}, {"GET", "/info"}, {"GET", "/system/df"},
  {"GET", "/libpod/containers/json"}, {"GET", "/"}, {"GET", ""}, {"POST", "/version"}, {"POST", "/_ping"},
  {"HEAD", "/_ping"}, {"CONNECT", "/containers/json"},
}
for _, d in ipairs(denied) do check("denied: " .. d[1] .. " " .. d[2], 403, req{method = d[1], path = v(d[2])}) end
check("unversioned container list", 403, req{path = "/containers/json", query = LIST_Q .. filters(LABEL_FILTER)})
check("unversioned image inspect", 403, req{path = "/images/" .. IMAGE .. "/json"})
check("unversioned container inspect", 403, req{path = "/containers/" .. ID .. "/json"})

-- Path variants: raw path, no normalisation ---------------------------------------------------------------------------
local lq = LIST_Q .. filters(LABEL_FILTER)
for _, p in ipairs({
  "/v" .. API .. "//containers/json", "/v" .. API .. "/./containers/json", "/v" .. API .. "/%2e/containers/json",
  "/v" .. API .. "/containers%2Fjson", "/v" .. API .. "/containers%2fjson", "/v" .. API .. "/Containers/json",
  "/v" .. API .. "/containers/json/", "/v" .. API .. "/v" .. API .. "/containers/json",
  "/V" .. API .. "/containers/json", "//v" .. API .. "/containers/json", "/v" .. API .. "/containers/JSON",
  "/v" .. API .. "/../containers/json", "v" .. API .. "/containers/json", "/v" .. API .. "containers/json",
}) do
  check("path variant " .. p, 403, req{path = p, query = lq})
end
for _, p in ipairs({
  "/containers/" .. ID:upper() .. "/json", "/containers/" .. ID:sub(1, 63) .. "/json",
  "/containers/" .. ID .. "0/json", "/containers/" .. ID .. "/json/", "/containers//" .. ID .. "/json",
  "/containers/" .. ID:sub(1, 12) .. "/json", "/containers/ss-" .. TOKEN .. "/json", "/containers/" .. ID .. "%2fjson",
  "/containers/" .. ID:sub(1, 63) .. "g/json",
}) do
  check("id path variant " .. p, 403, req{path = v(p)})
end
check("id route baseline", "allow", req{path = v("/containers/" .. ID .. "/json")})

-- API version prefix --------------------------------------------------------------------------------------------------
local major, minor = API:match("^(%d+)%.(%d+)$")
local function version_case(name, path, want)
  check(name, want, req{path = path, query = lq})
end
version_case("version equal to the daemon's", "/v" .. API .. "/containers/json", "allow")
version_case("version one below", "/v" .. major .. "." .. (tonumber(minor) - 1) .. "/containers/json", 403)
version_case("version one above", "/v" .. major .. "." .. (tonumber(minor) + 1) .. "/containers/json", 403)
version_case("the daemon's minimum version", "/v1.40/containers/json", 403)
version_case("version with a leading zero", "/v" .. major .. ".0" .. minor .. "/containers/json", 403)
version_case("version with another major", "/v2." .. minor .. "/containers/json", 403)
version_case("version without a minor", "/v" .. major .. "/containers/json", 403)
check("version reply as dockerd really writes it", "allow", req{path = v("/containers/json"), query = lq},
  {image = IMAGE, network = NETWORK, instance = INSTANCE}, fake_io{version = function() return (fixture("version.http10"):gsub("1%.56", API)) end})
check("version read returns nothing", 403, req{path = v("/containers/json"), query = lq}, CFG, fake_io{version = function() return nil, "boom" end})
check("version read raises", 403, req{path = v("/containers/json"), query = lq}, CFG, fake_io{version = function() error("boom") end})
check("version reply is garbage", 403, req{path = v("/containers/json"), query = lq}, CFG,
  fake_io{version = function() return "garbage" end})
check("version reply has no ApiVersion", 403, req{path = v("/containers/json"), query = lq}, CFG,
  fake_io{version = function() return "HTTP/1.0 200 OK\r\n\r\n{\"Version\":\"29\"}" end})
check("version reply ApiVersion is a number", 403, req{path = v("/containers/json"), query = lq}, CFG,
  fake_io{version = function() return "HTTP/1.0 200 OK\r\n\r\n{\"ApiVersion\":1.56}" end})
check("version reply status 500", 403, req{path = v("/containers/json"), query = lq}, CFG,
  fake_io{version = function() return "HTTP/1.0 500 Error\r\n\r\n{\"ApiVersion\":\"" .. API .. "\"}" end})
check("unversioned ping needs no version read", "allow", req{path = "/_ping"}, CFG,
  fake_io{version = function() error("must not be called") end})

-- Container list -------------------------------------------------------------------------------------------------------
local function list(name, want, query, cfg)
  check("list: " .. name, want, req{path = v("/containers/json"), query = query}, cfg)
end
list("baseline", "allow", lq)
list("no query at all", 403, "")
list("no filters", 403, "limit=-1&all=1&size=0&trunc_cmd=0")
list("filters alone", "allow", filters(LABEL_FILTER))
list("duplicate all", 403, "all=1&" .. lq)
list("duplicate filters", 403, lq .. "&" .. filters(LABEL_FILTER))
list("unknown key", 403, lq .. "&before=x")
list("limit changed", 403, "limit=5&" .. filters(LABEL_FILTER))
list("all changed", 403, "all=0&" .. filters(LABEL_FILTER))
list("size changed", 403, "size=1&" .. filters(LABEL_FILTER))
list("other instance", 403, filters('{"label": ["postern.managed=true", "postern.instance=other"]}'))
list("extra label", 403, filters('{"label": ["postern.managed=true", "postern.instance=' .. INSTANCE .. '", "x=y"]}'))
list("managed label alone", 403, filters('{"label": ["postern.managed=true"]}'))
list("labels swapped", 403, filters('{"label": ["postern.instance=' .. INSTANCE .. '", "postern.managed=true"]}'))
list("label as a string", 403, filters('{"label": "postern.managed=true"}'))
list("label and name together", 403, filters('{"label": ["postern.managed=true", "postern.instance=' .. INSTANCE .. '"], "name": ["^/ss-' .. TOKEN .. '$"]}'))
list("label and a second key", 403, filters('{"label": ["postern.managed=true", "postern.instance=' .. INSTANCE .. '"], "status": ["running"]}'))
list("double-encoded filters", 403, "filters=" .. enc(enc(LABEL_FILTER)))
list("filters not JSON", 403, "filters=%7Bx")
list("filters empty object", 403, filters("{}"))
list("filters empty", 403, "filters=")
list("filters with an escape", 403, "filters=" .. enc('{"label": ["postern.managed=true", "postern.instance=' .. INSTANCE .. '\\u0000"]}'))
list("name filter, unanchored", 403, filters('{"name": ["ss-' .. TOKEN .. '"]}'))
list("name filter, no leading slash", 403, filters('{"name": ["^ss-' .. TOKEN .. '$"]}'))
list("name filter, 23 hex", 403, filters('{"name": ["^/ss-' .. TOKEN:sub(1, 23) .. '$"]}'))
list("name filter, 25 hex", 403, filters('{"name": ["^/ss-' .. TOKEN .. 'a$"]}'))
list("name filter, wildcard", 403, filters('{"name": ["^/ss-.*$"]}'))
list("name filter, upper-case hex", 403, filters('{"name": ["^/ss-' .. TOKEN:upper() .. '$"]}'))
list("name filter, two names", 403, filters('{"name": ["^/ss-' .. TOKEN .. '$", "^/ss-' .. TOKEN .. '$"]}'))
list("malformed percent escape", 403, "filters=%zz")
list("malformed query", 403, "all")
list("upper-case key", 403, "ALL=1")
list("no instance id, label form", 403, lq, {image = IMAGE, network = NETWORK, instance = nil})
check("no instance id, name form still works", "allow", req{path = v("/containers/json"), query = LIST_Q .. filters(NAME_FILTER)},
  {image = IMAGE, network = NETWORK, instance = nil})

-- Image and network inspect -------------------------------------------------------------------------------------------
local img_path = v("/images/" .. pct(IMAGE, "%w_%.%-~/:") .. "/json")
check("image inspect baseline", "allow", req{path = img_path})
check("image inspect with a query", 403, req{path = img_path, query = "x=1"})
check("other image", 403, req{path = v("/images/alpine/json")})
check("image with a tag", 403, req{path = v("/images/" .. IMAGE .. ":evil/json")})
check("image with a digest", 403, req{path = v("/images/" .. IMAGE .. "@sha256:" .. string.rep("a", 64) .. "/json")})
check("image id", 403, req{path = v("/images/sha256:" .. string.rep("a", 64) .. "/json")})
check("image, suffixed name", 403, req{path = v("/images/" .. IMAGE .. "-test/json")})
check("empty configured image", 403, req{path = v("/images//json")}, {image = "", network = NETWORK, instance = INSTANCE})
local net_path = v("/networks/" .. pct(NETWORK, "%w_%.%-~/:"))
check("network inspect baseline", "allow", req{path = net_path})
check("network inspect with a query", 403, req{path = net_path, query = "verbose=true"})
check("network inspect with a body", 403, req{path = net_path, body = "x", headers = {["content-length"] = {"1"}}})
check("network id", 403, req{path = v("/networks/" .. string.rep("a", 64))})
check("empty configured network", 403, req{path = v("/networks/")}, {image = IMAGE, network = "", instance = INSTANCE})

-- Id-addressed routes: query rules ------------------------------------------------------------------------------------
local base_id = v("/containers/" .. ID)
check("inspect with a query", 403, req{path = base_id .. "/json", query = "size=1"})
check("start with a query", 403, req{method = "POST", path = base_id .. "/start", query = "detachKeys=x"})
check("stop t=10", "allow", req{method = "POST", path = base_id .. "/stop", query = "t=10"})
check("stop without t", "allow", req{method = "POST", path = base_id .. "/stop"})
check("stop t=11", 403, req{method = "POST", path = base_id .. "/stop", query = "t=11"})
check("stop t=10 twice", 403, req{method = "POST", path = base_id .. "/stop", query = "t=10&t=10"})
check("stop with a signal", 403, req{method = "POST", path = base_id .. "/stop", query = "t=10&signal=KILL"})
check("delete, docker-py's form", "allow", req{method = "DELETE", path = base_id, query = "v=False&link=False&force=True"})
check("delete force=1", 403, req{method = "DELETE", path = base_id, query = "v=False&link=False&force=1"})
check("delete v=True", 403, req{method = "DELETE", path = base_id, query = "v=True&link=False&force=True"})
check("delete link=True", 403, req{method = "DELETE", path = base_id, query = "v=False&link=True&force=True"})
check("delete with a name", 403, req{method = "DELETE", path = base_id, query = "v=False&link=False&force=True&name=x"})
check("inspect with a body", 403, req{path = base_id .. "/json", body = "x", headers = {["content-length"] = {"1"}}})

-- Ownership probe ------------------------------------------------------------------------------------------------------
local FIXTURE_ID = "b070c49b099dbac0f6c2a7796ee6d4d4b55f323e019b1e51e948471da1820094"
local FIXTURE_CFG = {image = IMAGE, network = NETWORK, instance = "l11r"}
local function probe_case(name, want, raw, cfg, id)
  id = id or FIXTURE_ID
  check("probe: " .. name, want, req{path = v("/containers/" .. id .. "/json")}, cfg or FIXTURE_CFG,
    fake_io{probe = function() return raw end})
end
for _, form in ipairs({"http10", "http11"}) do
  local one, empty = fixture("list-one." .. form), fixture("list-empty." .. form)
  probe_case("owned container (" .. form .. ")", "allow", one)
  probe_case("no such container (" .. form .. ")", 404, empty)
  probe_case("owned, another instance (" .. form .. ")", 403, one, {image = IMAGE, network = NETWORK, instance = "l11r2"})
  probe_case("owned, a different id asked (" .. form .. ")", 403, one, nil, string.rep("b", 64))
  probe_case("a 404 reply to the probe (" .. form .. ")", 403, fixture("inspect-404." .. form))
end
local one10 = fixture("list-one.http10")
local function edit(s, from, to)
  local a, b = s:find(from, 1, true)
  assert(a, "fixture lacks " .. from)
  return s:sub(1, a - 1) .. to .. s:sub(b + 1)
end
probe_case("instance label edited", 403, edit(one10, '"postern.instance":"l11r"', '"postern.instance":"other"'))
probe_case("managed label edited", 403, edit(one10, '"postern.managed":"true"', '"postern.managed":"false"'))
probe_case("instance label missing", 403, edit(one10, '"postern.instance":"l11r",', ""))
probe_case("managed label missing", 403, edit(one10, ',"postern.managed":"true"', ""))
probe_case("labels null", 403, edit(one10, '"Labels":{"desktop.docker.io/ports.scheme":"v2","postern.instance":"l11r","postern.managed":"true"}', '"Labels":null'))
probe_case("Id edited", 403, edit(one10, FIXTURE_ID, string.rep("d", 64)))
probe_case("label value written with an escape", 403, edit(one10, '"postern.managed":"true"', '"postern.managed":"tru\\u0065"'))
local entry = one10:match("\r\n\r\n%[(.*)%]$")
probe_case("two entries", 403, edit(one10, "\r\n\r\n[", "\r\n\r\n[" .. entry .. ","))
probe_case("one entry then a stray byte", 403, one10 .. "x")
probe_case("trailing newline after the list", 403, one10 .. "\n")
probe_case("pretty-printed empty list", 403, "HTTP/1.0 200 OK\r\n\r\n[\n]")
probe_case("empty list with a 500", 403, "HTTP/1.0 500 Internal Server Error\r\n\r\n[]")
probe_case("empty list, bare", 404, "HTTP/1.0 200 OK\r\n\r\n[]")
probe_case("truncated body", 403, one10:sub(1, #one10 - 40))
probe_case("error object instead of a list", 403, "HTTP/1.0 200 OK\r\n\r\n{\"message\":\"x\"}")
probe_case("HTML instead of JSON", 403, "HTTP/1.0 200 OK\r\n\r\n<html>[]</html>")
probe_case("entry is not an object", 403, "HTTP/1.0 200 OK\r\n\r\n[1]")
probe_case("duplicate Labels key", 403, edit(one10, '"Labels":{', '"Labels":{"postern.managed":"true",'))
probe_case("chunked, bad chunk size", 403, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n[]\r\n0\r\n\r\n")
probe_case("chunked, short chunk", 403, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n[]\r\n0\r\n\r\n")
probe_case("chunked, no terminator", 403, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n")
probe_case("chunked, data after the terminator", 403, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\nx")
probe_case("chunked, extension", 403, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;x=1\r\n[]\r\n0\r\n\r\n")
probe_case("chunked, well formed (control)", 404, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n")
probe_case("content-length matching", 404, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]")
probe_case("content-length not matching", 403, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n[]")
probe_case("no header terminator", 403, "HTTP/1.0 200 OK\r\n[]")
probe_case("not HTTP", 403, "[]")
probe_case("empty reply", 403, "")
check("probe returns nothing", 403, req{path = v("/containers/" .. ID .. "/json")}, CFG, fake_io{probe = function() return nil, "boom" end})
check("probe raises", 403, req{path = v("/containers/" .. ID .. "/json")}, CFG, fake_io{probe = function() error("boom") end})
check("probe is not asked about an unrelated request", "allow", req{path = "/version"}, CFG,
  fake_io{probe = function() error("must not be called") end})
check("probe is not asked about a wrong route", 403, req{method = "POST", path = v("/containers/" .. ID .. "/kill")}, CFG,
  fake_io{probe = function() error("must not be called") end})
check("no instance id", 403, req{path = v("/containers/" .. ID .. "/json")}, {image = IMAGE, network = NETWORK, instance = nil})
for _, r in ipairs({
  {"GET", "/json", ""}, {"POST", "/start", ""}, {"POST", "/stop", "t=10"}, {"DELETE", "", "v=False&link=False&force=True"},
}) do
  check("vanished id on " .. r[1] .. " " .. r[2], 404,
    req{method = r[1], path = v("/containers/" .. ID .. r[2]), query = r[3]}, CFG, fake_io{probe = function() return "HTTP/1.0 200 OK\r\n\r\n[]" end})
  check("foreign id on " .. r[1] .. " " .. r[2], 403,
    req{method = r[1], path = v("/containers/" .. ID .. r[2]), query = r[3]}, CFG, fake_io{probe = function(id) return owned_reply(id, "other") end})
end

-- Request-level header rules ------------------------------------------------------------------------------------------
local CT = {["content-type"] = {"application/json"}}
local function with(h, extra)
  local out = {}
  for k, val in pairs(h) do out[k] = val end
  for k, val in pairs(extra) do out[k] = val end
  return out
end
local function ping(name, want, headers) check("headers: " .. name, want, req{path = v("/_ping"), headers = headers}) end
ping("none", "allow", {})
ping("Transfer-Encoding", 403, {["transfer-encoding"] = {"chunked"}})
ping("Transfer-Encoding twice", 403, {["transfer-encoding"] = {"chunked", "chunked"}})
ping("Transfer-Encoding identity", 403, {["transfer-encoding"] = {"identity"}})
ping("Upgrade", 403, {upgrade = {"h2c"}})
ping("Expect", 403, {expect = {"100-continue"}})
ping("two Content-Length", 403, {["content-length"] = {"0", "0"}})

local function create_with(name, want, over, body)
  body = body or create_wire.body
  local r = {
    method = "POST", path = create_wire.path, query = create_wire.query, body = body,
    headers = with(CT, {["content-length"] = {tostring(#body)}}),
  }
  for k, val in pairs(over or {}) do
    if k == "headers" then r.headers = val else r[k] = val end
  end
  check("create: " .. name, want, req(r))
end
create_with("baseline", "allow")
create_with("no Content-Length", 403, {headers = CT})
create_with("two Content-Length", 403, {headers = with(CT, {["content-length"] = {tostring(#create_wire.body), tostring(#create_wire.body)}})})
create_with("Content-Length mismatch", 403, {body_size = #create_wire.body + 1})
create_with("buffered shorter than declared", 403, {body_len = #create_wire.body - 1})
create_with("Transfer-Encoding", 403, {headers = with(CT, {["content-length"] = {tostring(#create_wire.body)}, ["transfer-encoding"] = {"chunked"}})})
create_with("Upgrade", 403, {headers = with(CT, {["content-length"] = {tostring(#create_wire.body)}, upgrade = {"websocket"}})})
create_with("Expect", 403, {headers = with(CT, {["content-length"] = {tostring(#create_wire.body)}, expect = {"100-continue"}})})
create_with("no Content-Type", 403, {headers = {["content-length"] = {tostring(#create_wire.body)}}})
create_with("text/plain", 403, {headers = {["content-length"] = {tostring(#create_wire.body)}, ["content-type"] = {"text/plain"}}})
create_with("form-urlencoded", 403, {headers = {["content-length"] = {tostring(#create_wire.body)}, ["content-type"] = {"application/x-www-form-urlencoded"}}})
create_with("json with a charset", 403, {headers = {["content-length"] = {tostring(#create_wire.body)}, ["content-type"] = {"application/json; charset=utf-8"}}})
create_with("two Content-Type, one json", 403, {headers = {["content-length"] = {tostring(#create_wire.body)}, ["content-type"] = {"text/plain", "application/json"}}})
create_with("two Content-Type, both json", 403, {headers = {["content-length"] = {tostring(#create_wire.body)}, ["content-type"] = {"application/json", "application/json"}}})

-- Create: query and name ------------------------------------------------------------------------------------------------
local function create_q(name, want, query) create_with("query " .. name, want, {query = query}) end
create_q("baseline", "allow", "name=ss-" .. TOKEN)
create_q("no name", 403, "")
create_q("two names", 403, "name=ss-" .. TOKEN .. "&name=ss-" .. TOKEN)
create_q("23 hex", 403, "name=ss-" .. TOKEN:sub(1, 23))
create_q("25 hex", 403, "name=ss-" .. TOKEN .. "a")
create_q("upper-case prefix", 403, "name=SS-" .. TOKEN)
create_q("upper-case hex", 403, "name=ss-" .. TOKEN:upper())
create_q("non-hex", 403, "name=ss-" .. TOKEN:sub(1, 23) .. "g")
create_q("other prefix", 403, "name=sx-" .. TOKEN)
create_q("platform", 403, "name=ss-" .. TOKEN .. "&platform=linux/amd64")
create_q("percent-encoded dash decodes to the same valid name", "allow", "name=ss%2D" .. TOKEN)
create_q("trailing newline", 403, "name=ss-" .. TOKEN .. "%0A")
check("create: with no instance id", 403, req{
  method = "POST", path = create_wire.path, query = create_wire.query, body = create_wire.body,
  headers = with(CT, {["content-length"] = {tostring(#create_wire.body)}}),
}, {image = IMAGE, network = NETWORK, instance = nil})

-- Create: body ----------------------------------------------------------------------------------------------------------
local base = create_wire.body
local function replace(from, to)
  local a, b = base:find(from, 1, true)
  assert(a, "baseline body lacks " .. from)
  return base:sub(1, a - 1) .. to .. base:sub(b + 1)
end
local function remove(piece)
  local a, b = base:find(", " .. piece, 1, true)
  if not a then a, b = base:find(piece .. ", ", 1, true) end
  assert(a, "baseline body lacks " .. piece)
  return base:sub(1, a - 1) .. base:sub(b + 1)
end
local function body_case(name, body)
  assert(body ~= base, name .. ": the case did not change the body")
  create_with("body " .. name, 403, nil, body)
end
local function add_top(piece) return base:sub(1, -2) .. ", " .. piece .. "}" end
local function add_host(piece) return replace('"HostConfig": {', '"HostConfig": {' .. piece .. ", ") end

for _, extra in ipairs({
  '"Cmd": ["sh"]', '"Entrypoint": ["sh"]', '"User": "root"', '"WorkingDir": "/"', '"Volumes": {"/x": {}}',
  '"ExposedPorts": {"80/tcp": {}}', '"Healthcheck": {"Test": ["NONE"]}', '"Hostname": "x"', '"StopSignal": "SIGKILL"',
  '"image": "alpine"', '"IMAGE": "alpine"', '"labels": {}', '"hostconfig": {}', '"Image ": "alpine"', '"Pad": 1',
}) do
  body_case("top-level " .. extra, add_top(extra))
end
for _, extra in ipairs({
  '"Binds": ["/:/h"]', '"Privileged": true', '"CapAdd": ["SYS_ADMIN"]', '"Devices": [{"PathOnHost": "/dev/sda"}]',
  '"PidMode": "host"', '"IpcMode": "host"', '"UsernsMode": "host"', '"UTSMode": "host"', '"CgroupnsMode": "host"',
  '"VolumesFrom": ["portal"]', '"Mounts": [{"Type": "bind", "Source": "/", "Target": "/h"}]',
  '"PortBindings": {"80/tcp": [{"HostPort": "80"}]}', '"PublishAllPorts": true', '"Sysctls": {"a": "b"}',
  '"Runtime": "runc"', '"Links": ["x"]', '"ExtraHosts": ["a:1.1.1.1"]', '"Dns": ["1.1.1.1"]', '"AutoRemove": true',
  '"Cgroup": "x"', '"CgroupParent": "x"', '"GroupAdd": ["0"]', '"OomScoreAdj": -1000', '"ShmSize": 1',
  '"Ulimits": [{"Name": "nofile", "Soft": 1, "Hard": 1}]', '"StorageOpt": {"a": "b"}', '"VolumeDriver": "x"',
  '"Isolation": "hyperv"', '"MaskedPaths": []', '"ReadonlyPaths": []', '"networkmode": "host"', '"capdrop": ["ALL"]',
}) do
  body_case("HostConfig " .. extra, add_host(extra))
end
for _, mode in ipairs({"host", "none", "bridge", "container:" .. string.rep("a", 64), "default", NETWORK .. "x"}) do
  body_case("NetworkMode " .. mode, replace('"NetworkMode": "' .. NETWORK .. '"', '"NetworkMode": "' .. mode .. '"'))
end
body_case("NetworkMode missing", remove('"NetworkMode": "' .. NETWORK .. '"'))
body_case("NetworkMode twice", add_host('"NetworkMode": "host"'))

-- Image
for _, img in ipairs({
  IMAGE .. ":evil", IMAGE .. "-test", IMAGE .. "@sha256:" .. string.rep("a", 64), "sha256:" .. string.rep("a", 64),
  "alpine", "", IMAGE .. " ", " " .. IMAGE, IMAGE:upper(),
}) do
  body_case("Image " .. img, replace('"Image": "' .. IMAGE .. '"', '"Image": "' .. img .. '"'))
end
body_case("Image missing", remove('"Image": "' .. IMAGE .. '"'))
body_case("Image twice, evil first", replace('"Image": "' .. IMAGE .. '"', '"Image": "alpine", "Image": "' .. IMAGE .. '"'))
body_case("Image twice, evil last", replace('"Image": "' .. IMAGE .. '"', '"Image": "' .. IMAGE .. '", "Image": "alpine"'))
body_case("Image as a list", replace('"Image": "' .. IMAGE .. '"', '"Image": ["' .. IMAGE .. '"]'))

-- Env
local env = base:match('"Env": (%b[])')
assert(env, "baseline body has no Env")
for name, to in pairs({
  two = env:sub(1, -2) .. ', "LD_PRELOAD=/x"]', other_name = '["FOO=bar"]', empty = "[]", none = "null",
  empty_value = '["SS_CONFIG="]', bad_char = '["SS_CONFIG=ab cd"]', lower_name = '["ss_config=QUJD"]',
  newline = '["SS_CONFIG=QUJD\\n"]', object = '{"SS_CONFIG": "QUJD"}', string = '"SS_CONFIG=QUJD"',
  two_ss = '["SS_CONFIG=QUJD", "SS_CONFIG=QUJD"]', number = "[1]",
}) do
  body_case("Env " .. name, replace('"Env": ' .. env, '"Env": ' .. to))
end
body_case("Env missing", remove('"Env": ' .. env))

-- Labels
local labels = base:match('"Labels": (%b{})')
assert(labels, "baseline body has no Labels")
for name, to in pairs({
  extra_key = labels:sub(1, -2) .. ', "x": "y"}', spec = labels:sub(1, -2) .. ', "postern.spec": "1"}',
  other_instance = '{"postern.managed": "true", "postern.instance": "other"}',
  not_managed = '{"postern.managed": "false", "postern.instance": "' .. INSTANCE .. '"}',
  no_instance = '{"postern.managed": "true"}', no_managed = '{"postern.instance": "' .. INSTANCE .. '"}',
  empty = "{}", none = "null", list = '["postern.managed=true"]',
}) do
  body_case("Labels " .. name, replace('"Labels": ' .. labels, '"Labels": ' .. to))
end
body_case("Labels missing", remove('"Labels": ' .. labels))

-- Flags that must be false
for _, k in ipairs({"Tty", "OpenStdin", "StdinOnce", "AttachStdin", "AttachStdout", "AttachStderr", "NetworkDisabled"}) do
  body_case(k .. " true", replace('"' .. k .. '": false', '"' .. k .. '": true'))
  body_case(k .. " null", replace('"' .. k .. '": false', '"' .. k .. '": null'))
end

-- The five hardening keys, the three older ones, and Tmpfs
local function host_value(key) return base:match('"' .. key .. '": ([^,}]+)') or base:match('"' .. key .. '": (%b[])') or base:match('"' .. key .. '": (%b{})') end
local function swap(key, to)
  local from = base:match('"' .. key .. '": (%b[])') or base:match('"' .. key .. '": (%b{})') or host_value(key)
  assert(from, "baseline body lacks " .. key)
  return replace('"' .. key .. '": ' .. from, '"' .. key .. '": ' .. to), from
end
for key, variants in pairs({
  CapDrop = {'["ALL", "NET_ADMIN"]', "[]", '["NET_ADMIN"]', '"ALL"', "null", '["all"]', '{"0": "ALL"}'},
  SecurityOpt = {'["seccomp=unconfined"]', "[]", '["no-new-privileges:false"]', '["no-new-privileges:true", "apparmor=unconfined"]', "null"},
  ReadonlyRootfs = {"false", "null", '"true"', "1"},
  Memory = {"0", "1073741824", "536870913", "-1", "null", '"536870912"', "536870912.0", "5.36870912e8"},
  PidsLimit = {"-1", "0", "1025", "null", '"1024"', "1.024e3"},
  Init = {"false", "null", '"true"'},
  RestartPolicy = {'{"Name": "always"}', '{"Name": "unless-stopped", "MaximumRetryCount": 3}', "{}", "null", '"unless-stopped"'},
  LogConfig = {'{"Type": "json-file", "Config": {}}', '{"Type": "none", "Config": {"a": "b"}}', '{"Type": "none"}', "{}", "null"},
  Tmpfs = {
    '{"/tmp": ""}', '{"/tmp": "", "/home/nonroot/.cache": "exec", "/x": ""}', '{"/tmp": "exec", "/home/nonroot/.cache": "exec"}',
    '{"/tmp": "", "/home/nonroot/.cache": "rw"}', '{"/home/nonroot/.cache": "exec"}', "{}", "null",
    '{"/tmp": "", "/home/nonroot/.cache": "exec,suid"}', '{"/tmp": "", "/": "exec"}',
  },
}) do
  for _, to in ipairs(variants) do
    body_case(key .. " = " .. to, (swap(key, to)))
  end
  local _, from = swap(key, "null")
  body_case(key .. " removed", remove('"' .. key .. '": ' .. from))
end

-- NetworkingConfig is optional, and exactly {network: null}
local nc = base:match('"NetworkingConfig": (%b{})')
assert(nc, "baseline body has no NetworkingConfig")
local without_nc = remove('"NetworkingConfig": ' .. nc)
create_with("body without NetworkingConfig", "allow", nil, without_nc)
for name, to in pairs({
  other_network = '{"host": null}', two = '{"' .. NETWORK .. '": null, "host": null}', non_null = '{"' .. NETWORK .. '": {"Aliases": ["x"]}}',
  empty = "{}", list = "[]", none = "null",
}) do
  body_case("NetworkingConfig " .. name, replace('"NetworkingConfig": ' .. nc, '"NetworkingConfig": ' .. to))
end

-- The strict JSON subset: every byte-level trick fails closed
body_case("duplicate key at depth 2", replace('"Init": true', '"Init": true, "Init": true'))
body_case("escape in a key", replace('"Image"', '"Im\\u0061ge"'))
body_case("escape in a value", replace('"Image": "' .. IMAGE, '"Image": "' .. IMAGE:sub(1, 5) .. "\\u006c" .. IMAGE:sub(7)))
body_case("non-ASCII byte", replace(IMAGE, IMAGE .. "\xc3\xa9"))
body_case("control byte", replace('"Init": true', '"Init":\ttrue'))
body_case("trailing data", base .. " x")
body_case("two documents", base .. base)
body_case("leading garbage", "x" .. base)
body_case("not an object", "[" .. base .. "]")
body_case("empty", "")
body_case("truncated", base:sub(1, -2))
body_case("single quotes", (base:gsub('"', "'")))
body_case("trailing comma", base:sub(1, -2) .. ",}")
body_case("deep nesting", replace('"Init": true', '"Init": true, "X": [[[[[[[[[[]]]]]]]]]]'))
body_case("number with a leading zero", replace('"PidsLimit": ' .. P.SS_PIDS_LIMIT, '"PidsLimit": 0' .. P.SS_PIDS_LIMIT))
body_case("comment", base .. " // x")
body_case("NaN", replace('"Memory": ' .. P.SS_MEMORY_BYTES, '"Memory": NaN'))
create_with("exactly 8192 bytes of valid JSON", "allow", nil, base .. string.rep(" ", 8192 - #base))
create_with("8193 bytes of valid JSON", 403, nil, base .. string.rep(" ", 8193 - #base))

-- Config from the environment -------------------------------------------------------------------------------------------
local function env_cfg(vars) return P.config_from_env(function(k) return vars[k] end) end
eq("config: override wins", env_cfg{INSTANCE_ID = "a", COMPOSE_PROJECT_NAME = "b"}.instance, "a")
eq("config: project name", env_cfg{COMPOSE_PROJECT_NAME = "b"}.instance, "b")
eq("config: both empty", env_cfg{INSTANCE_ID = "", COMPOSE_PROJECT_NAME = ""}.instance, nil)
eq("config: unset", env_cfg{}.instance, nil)
eq("config: whitespace stripped", env_cfg{INSTANCE_ID = "  a  "}.instance, "a")
eq("config: whitespace override falls back", env_cfg{INSTANCE_ID = "   ", COMPOSE_PROJECT_NAME = "b"}.instance, "b")
eq("config: image verbatim", env_cfg{SHADOWSOCKS_IMAGE = "x/y:z"}.image, "x/y:z")
eq("config: image unset", env_cfg{}.image, "")
eq("config: network verbatim", env_cfg{SHADOWSOCKS_NETWORK = "n"}.network, "n")
eq("config: network unset", env_cfg{}.network, "")
for _, bad in ipairs({"-a", ".a", "_a", "a b", "a\"b", "a,b", "a/b", "a\\b", "a%b", "a&b", "a=b", "a\nb", string.rep("a", 64), "é"}) do
  eq("config: instance " .. bad:gsub("%c", "?"), env_cfg{INSTANCE_ID = bad}.instance, nil)
end
eq("config: instance of 63 characters", env_cfg{INSTANCE_ID = string.rep("a", 63)}.instance, string.rep("a", 63))
eq("config: instance with dot, dash, underscore", env_cfg{INSTANCE_ID = "a.b-c_d"}.instance, "a.b-c_d")

-- JSON parser contract ----------------------------------------------------------------------------------------------------
local function parses(mode, s) return P.parse_json(s, mode) ~= nil end
eq("json request: object", parses("request", '{"a": [1, true, null, "x"]}'), true)
eq("json request: no escapes", parses("request", '{"a": "\\n"}'), false)
eq("json request: no fractions", parses("request", '{"a": 1.5}'), false)
eq("json request: no exponents", parses("request", '{"a": 1e3}'), false)
eq("json request: no newline", parses("request", '{"a":\n1}'), false)
eq("json reply: compact object", parses("reply", '{"a":[1,true,null,"x\\n\\u00e9"],"b":1.5e3}'), true)
eq("json reply: no whitespace between tokens", parses("reply", '{"a": 1}'), false)
eq("json reply: bad escape", parses("reply", '{"a":"\\q"}'), false)
eq("json reply: raw control byte in a string", parses("reply", '{"a":"\n"}'), false)
eq("json reply: UTF-8 passes", parses("reply", '{"a":"\xc3\xa9"}'), true)
eq("json reply: duplicate key", parses("reply", '{"a":1,"a":2}'), false)
eq("json reply: trailing data", parses("reply", '{"a":1}x'), false)
eq("json reply: depth 32 ok", parses("reply", string.rep("[", 32) .. string.rep("]", 32)), true)
eq("json reply: depth 33 denied", parses("reply", string.rep("[", 33) .. string.rep("]", 33)), false)

core.register_init(function()
  print(string.format("%d checks, %d failed", total, fails))
  io.stdout:flush()
  os.exit(fails == 0 and 0 or 3)
end)
