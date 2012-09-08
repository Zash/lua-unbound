-- libunbound binding by Kim Alvefur

local rawget, rawset = rawget, rawset;
local setmetatable = setmetatable;
local t_insert = table.insert;
local t_concat = table.concat;

local log = require "util.logger".init("ldns");
local config = require "core.configmanager";
local resolvconf = config.get("*", "resolvconf");
local hoststxt = config.get("*", "hoststxt");

local gettime = require"socket".gettime;
local dns_utils = require"util.dns";
local classes, types, errors = dns_utils.classes, dns_utils.types, dns_utils.errors;
local parsers = dns_utils.parsers;

-- FFI setup
local ffi = require "ffi";
local char = ffi.new("char *");
local function tochar(s)
	return ffi.cast(char, s);
end

local unbound = require"lib.unbound";
local ctx = unbound.ub_ctx_create();
local ub_fd = unbound.ub_fd(ctx);

unbound.ub_ctx_add_ta(ctx, tochar(". IN DS 19036 8 2 "
	.."49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"));

if resolvconf then
	unbound.ub_ctx_resolvconf(ctx, tochar(resolvconf));
end
if hoststxt then
	unbound.ub_ctx_hosts(ctx, tochar(hoststxt));
end

local function nuke()
	if ctx then
		unbound.ub_ctx_delete(ctx);
		ctx = nil;
		ub_fd = nil;
		unbound = nil;
	end
end

if prosody then
	prosody.events.add_handler("server-stopped", nuke);
end

local callbacks = setmetatable({}, {
	__index = function(t,n)
		local nt = {};
		rawset(t,n,nt);
		return nt;
	end
});

local function process()
	unbound.ub_process(ctx);
end

local noop = function() end;

local ub_listener = {
	onincoming = process,
	ondisconnect = nuke,

	receive = noop,
	onconnect = noop,
	ondrain = noop,
	onstatus = noop,
};

local ub_conn = {
	getfd = function()
		return ub_fd;
	end,

	send = noop,
	close = noop,
	--dirty = noop,
	receive = noop,
	settimeout = noop,
	shutdown = noop,
}

local server = require "net.server";
if server.event and server.addevent then
	error("libevent doesnt't appear to be working correctly yet"); -- FIXME
	--server.addevent(ub_fd, server.event.EV_READ + server.event.EV_TIMEOUT, process, 5);
elseif server.wrapclient then
	server.wrapclient(ub_conn, "dns", 0, ub_listener, "*a" );
end

local answer_mt = {
	__tostring = function(self)
		local h = ("Status: %s"):format(self.status[1]);
		if self.secure then
			h =  h .. ", Secure";
		elseif self.bogus then
			h = h .. (", Bogus: %s"):format(self.bogus);
		end
		local t = { h };
		for i=1,#self do
			t[i+1]=tostring(v);
		end
		return t_concat(t, "\n");
	end,
};

local handle_answer = ffi.cast("ub_callback_t", function(_, err, result)
	if err == 0 and result[0].havedata then
		local gotdataat = gettime();
		local result = result[0];
		local qname, qclass, qtype = ffi.string(result.qname), classes[result.qclass], types[result.qtype];
		local q = qname.." "..qclass.." "..qtype;
		local a = {
			name = qname,
			type = qtype,
			class = qclass,
			rcode = result.rcode;
			status = errors[result.rcode];
			secure = result.secure == 1;
			bogus = result.bogus == 1 and ffi.string(result.why_bogus) or nil;
		};

		local qtype_ = qtype:lower();
		local i = 0;
		while result.len[i] > 0 do
			local len = result.len[i];
			local data = ffi.string(result.data[i], len);
			i = i + 1;

			local parsed = parsers[qtype](data);
			local rr = {
				[qtype_] = parsed;
			};
			if parsed then 
				local s = q .. " " .. tostring(parsed);
				setmetatable(rr, {__tostring=function()return s; end}); -- What could possibly go wrong?
			end
			a[i] = rr;
		end
		setmetatable(a, answer_mt);

		local cbs
		cbs, callbacks[q] = callbacks[q], nil;

		log("debug", "Results for %s: %s (%s, %f sec)", q, a.rcode == 0 and (#a .. " items") or a.status[2],
		a.secure and "Secure" or a.bogus or "Insecure", gotdataat - cbs.t);

		if #a == 0 then
			a=nil -- COMPAT
		end
		for i = 1, #cbs do
			cbs[i](a);
		end
	end
	return unbound.ub_resolve_free(result);
end);

local function lookup(callback, qname, qtype, qclass)
	qtype = qtype and qtype:upper() or "A";
	qclass = qclass and qclass:upper() or "IN";
	local ntype, nclass = types[qtype], classes[qclass];
	if not ntype or not nclass then
		return nil, "Invalid type or class"
	end
	local q = qname.." "..qclass.." "..qtype;
	local qcb = callbacks[q];
	qcb.t = qcb.t or gettime();
	local n = #qcb;
	t_insert(qcb, callback);
	if n == 0 then
		log("debug", "Resolve %s",q);
		local ok = unbound.ub_resolve_async(ctx, tochar(qname),
			ntype, nclass, nil, handle_answer, nil);
		if ok ~= 0 then
			log("warn", "Something went wrong, %s", ffi.string(unbound.ub_strerror(ok)));
		end
	else
		log("debug", "Already %d waiting callbacks for %s", n, q);
	end
end

-- Public API
return { lookup = lookup, peek = noop, settimeout = noop, pulse = process };
