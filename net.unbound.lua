-- libunbound based net.adns replacement for Prosody IM
-- Copyright (C) 2013-2014 Kim Alvefur
--
-- This file is MIT/X11 licensed.

local setmetatable = setmetatable;
local tostring = tostring;
local t_concat = table.concat;
local s_format = string.format;
local s_lower = string.lower;
local s_upper = string.upper;
local noop = function() end;
local zero = function() return 0 end;
local truop = function() return true; end;

local log = require "util.logger".init("unbound");
local server = require "net.server";
local libunbound = require"util.lunbound";

local gettime = require"socket".gettime;
local dns_utils = require"util.dns";
local classes, types, errors = dns_utils.classes, dns_utils.types, dns_utils.errors;
local parsers = dns_utils.parsers;

local unbound_config;
if prosody then
	unbound_config = config.get("*", "unbound");
	prosody.events.add_handler("config-reloaded", function()
		unbound_config = config.get("*", "unbound");
	end);
end
-- Note: libunbound will default to using root hints if resolvconf is unset

local unbound = libunbound.new(unbound_config);

local function connect_server(unbound, server)
	if server.event and server.addevent then
		local EV_READ = server.event.EV_READ;
		local function event_callback()
			unbound:process();
			return EV_READ;
		end
		return server.addevent(unbound:getfd(), EV_READ, event_callback)
	elseif server.wrapclient then
		local conn = {
			getfd = function()
				return unbound:getfd();
			end,

			send = zero,
			receive = noop,
			settimeout = noop,
		}

		local function process()
			unbound:process();
		end
		local listener = {
			onincoming = process,

			onconnect = noop,
			ondisconnect = noop,
			onreadtimeout = truop,
		};
		return server.wrapclient(conn, "dns", 0, listener, "*a" );
	end
end

local server_conn = connect_server(unbound, server);

local answer_mt = {
	__tostring = function(self)
		if self._string then return self._string end
		local h = s_format("Status: %s", errors[self.status]);
		if self.secure then
			h =  h .. ", Secure";
		elseif self.bogus then
			h = h .. s_format(", Bogus: %s", self.bogus);
		end
		local t = { h };
		for i=1,#self do
			t[i+1]=self.qname.."\t"..classes[self.qclass].."\t"..types[self.qtype].."\t"..tostring(self[i]);
		end
		local _string = t_concat(t, "\n");
		self._string = _string;
		return _string;
	end,
};

local waiting_queries = { };

local function prep_answer(a)
	if not a then return end
	local status = errors[a.rcode];
	local qclass = classes[a.qclass];
	local qtype = types[a.qtype];
	a.status, a.class, a.type = status, qclass, qtype;

	local t = s_lower(qtype);
	local rr_mt = { __index = a, __tostring = function(self) return tostring(self[t]) end };
	local parser = parsers[qtype];
	for i=1, #a do
		if a.bogus then
			-- Discard bogus data
			a[i] = nil;
		else
			a[i] = setmetatable({
				[t] = parser(a[i]);
			}, rr_mt);
		end
	end
	return setmetatable(a, answer_mt);
end

local function lookup(callback, qname, qtype, qclass)
	qtype = qtype and s_upper(qtype) or "A";
	qclass = qclass and s_upper(qclass) or "IN";
	local ntype, nclass = types[qtype], classes[qclass];
	local startedat = gettime();
	local ok, err;
	local function callback_wrapper(a, err)
		local gotdataat = gettime();
		waiting_queries[ok] = nil;
		prep_answer(a);
		log("debug", "Results for %s %s %s: %s (%s, %f sec)", qname, qclass, qtype, a.rcode == 0 and (#a .. " items") or a.status,
			a.secure and "Secure" or a.bogus or "Insecure", gotdataat - startedat); -- Insecure as in unsigned
		return callback(a, err);
	end
	log("debug", "Resolve %s %s %s", qname, qclass, qtype);
	ok, err = unbound:resolve_async(callback_wrapper, qname, ntype, nclass);
	if ok then
		waiting_queries[ok] = callback;
	else
		log("warn", err);
	end
	return ok, err;
end

local function cancel(id)
	local cb = waiting_queries[id];
	unbound:cancel(id);
	if cb then
		cb(nil, "canceled");
		waiting_queries[id] = nil;
	end
	return true;
end

-- Reinitiate libunbound context, drops cache
local function purge()
	for id in pairs(waiting_queries) do
		cancel(id);
	end
	if server_conn then
		server_conn:close();
	end
	unbound = libunbound.new(unbound_config);
	server_conn = connect_server(unbound, server);
	return true;
end

local function not_implemented()
	error "not implemented";
end
-- Public API
return {
	lookup = lookup,
	cancel = cancel;
	new_async_socket = not_implemented;
	dns = {
		cancel = cancel;
		cache = noop;
		socket_wrapper_set = noop;
		settimeout = noop;
		query = noop;
		purge = purge;
		random = noop;
		peek = noop;

		types = types;
		classes = classes;
	};
};

