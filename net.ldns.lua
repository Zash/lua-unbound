-- libunbound based net.adns replacement for Prosody IM
-- Copyright (c) 2012 Kim Alvefur
--
-- This file is MIT/X11 licensed.

local setmetatable = setmetatable;
local t_insert = table.insert;
local t_concat = table.concat;
local noop = function() end;

local log = require "util.logger".init("ldns");
local config = require "core.configmanager";

local gettime = require"socket".gettime;
local dns_utils = require"util.dns";
local classes, types, errors = dns_utils.classes, dns_utils.types, dns_utils.errors;
local parsers = dns_utils.parsers;

local unbound = require"lib.unbound".new {
	trusted = { [[. IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5]] };
	resolvconf = config.get("*", "resolvconf");
	hoststxt = config.get("*", "hoststxt");
};
-- Note: libunbound will default to using root hints if resolvconf is unset

local function process()
	unbound:process();
end

local listener = {
	onincoming = process,

	ondisconnect = noop,
	receive = noop,
	onconnect = noop,
	ondrain = noop,
	onstatus = noop,
};

local conn = {
	getfd = function()
		return unbound:getfd();
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
	local EV_READ = server.event.EV_READ;
	local function cb()
		unbound:process();
		return EV_READ;
	end
	unbound._leh = server.addevent(unbound:getfd(), EV_READ, cb)
elseif server.wrapclient then
	server.wrapclient(conn, "dns", 0, listener, "*a" );
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
			t[i+1]=tostring(self[i]);
		end
		return t_concat(t, "\n");
	end,
};

local callbacks = setmetatable({}, {
	__index = function(t,n)
		local nt = {};
		t[n]=nt;
		return nt;
	end
});

function unbound:callback(a)
	local gotdataat = gettime();
	local status = errors[a.rcode];
	local qclass = classes[a.qclass];
	local qtype = types[a.qtype];
	a.status, a.class, a.type = status, qclass, qtype;
	local q = a.qname .. " " .. qclass .. " " .. qtype;

	local t = qtype:lower();
	local rr_mt = {__index=a,__tostring=function(self) return tostring(self[t]) end};
	for i=1, #a do
		a[i] = setmetatable({
			[t] = parsers[qtype](a[i]);
		}, rr_mt);
	end
	setmetatable(a, answer_mt);

	local cbs;
	cbs, callbacks[q] = callbacks[q], nil;

	log("debug", "Results for %s: %s (%s, %f sec)", q, a.rcode == 0 and (#a .. " items") or a.status[2],
		a.secure and "Secure" or a.bogus or "Insecure", gotdataat - cbs.t); -- Insecure as in unsigned

	--[[
	if #a == 0 then
		a=nil -- COMPAT
	end
	--]]
	for i = 1, #cbs do
		cbs[i](a);
	end
end

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
		log("debug", "Resolve %s", q);
		local ok, err = unbound:lookup(qname, ntype, nclass);
		if not ok then
			log("warn", "Something went wrong, %s", err);
		end
	else
		log("debug", "Already %d waiting callbacks for %s", n, q);
	end
end

-- Reinitiate libunbound context, drops cache
local function purge()
	return unbound:reset();
end

-- Public API
return { lookup = lookup, peek = noop, settimeout = noop, pulse = process, purge = purge };
