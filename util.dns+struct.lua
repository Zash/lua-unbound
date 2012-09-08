-- libunbound based net.adns replacement for Prosody IM
-- Copyright (c) 2012 Kim Alvefur
-- Copyright (c) 2012 Waqas Hussain
--
-- This file is MIT/X11 licensed.

local pairs = pairs;
local setmetatable = setmetatable;
local table = table;
local t_concat = table.concat;
local t_insert = table.insert;
local c_unpack = require"struct".unpack;

-- Converted from
-- http://www.iana.org/assignments/dns-parameters
-- 2012-04-13

local classes = { IN=1, CH=3, HS=4, NONE=254, ANY=255, }
for c, v in pairs(classes) do classes[v] = c; end

local types = { A = 1, NS = 2, MD = 3, MF = 4, CNAME = 5, SOA = 6, MB 
= 7, MG = 8, MR = 9, NULL = 10, WKS = 11, PTR = 12, HINFO = 13, MINFO = 
14, MX = 15, TXT = 16, RP = 17, AFSDB = 18, X25 = 19, ISDN = 20, RT = 21, 
NSAP = 22, ["NSAP-PTR"] = 23, SIG = 24, KEY = 25, PX = 26, GPOS = 27, 
AAAA = 28, LOC = 29, NXT = 30, EID = 31, NIMLOC = 32, SRV = 33, ATMA = 
34, NAPTR = 35, KX = 36, CERT = 37, A6 = 38, DNAME = 39, SINK = 40, OPT = 
41, APL = 42, DS = 43, SSHFP = 44, IPSECKEY = 45, RRSIG = 46, NSEC = 47, 
DNSKEY = 48, DHCID = 49, NSEC3 = 50, NSEC3PARAM = 51, TLSA = 52, HIP = 
55, NINFO = 56, RKEY = 57, TALINK = 58, CDS = 59, SPF = 99, TKEY = 249, 
TSIG = 250, IXFR = 251, AXFR = 252, MAILB = 253, MAILA = 254, ANY = 255, 
URI = 256, CAA = 257, TA = 32768, DLV = 32769, }
for c, v in pairs(types) do types[v] = c; end

local errors = {
[0] = { "NoError", "No Error" },
{ "FormErr", "Format Error" },
{ "ServFail", "Server Failure" },
{ "NXDomain", "Non-Existent Domain" },
{ "NotImp", "Not Implemented" },
{ "Refused", "Query Refused" },
{ "YXDomain", "Name Exists when it should not" },
{ "YXRRSet", "RR Set Exists when it should not" },
{ "NXRRSet", "RR Set that should exist does not" },
{ "NotAuth", "Server Not Authoritative for zone" },
{ "NotZone", "Name not contained in zone" },
};

-- Simplified versions of Waqas DNS parsers
-- converted to use unpack from the struct rock
-- Only the per RR parsers are needed and only feed a single RR

local parsers = {};

local function readDnsName(packet, pos)
	local r, pos = {}, pos or 1;
	while pos < #packet do
		local s, n = c_unpack(">Bc0", packet, pos);
		t_insert(r, s);
		pos = n;
		if #s == 0 then break end
	end
	return t_concat(r, "."), pos;
end

-- These are just simple names.
parsers.CNAME = readDnsName;
parsers.NS = readDnsName
parsers.PTR = readDnsName;

local soa_mt = {
	__tostring = function(t)
		return ("%s %s %d %d %d %d %d"):format(t.mname, t.rname, t.serial, t.refresh, t.retry, t.expire, t.minimum);
	end
};
function parsers.SOA(packet)
	local mname, offset = readDnsName(packet, 1);
	local rname, offset = readDnsName(packet, offset);
	local serial, refresh, retry, expire, minimum =
		c_unpack(">I4I4I4I4I4", packet, offset);
	return setmetatable({
		mname = mname;
		rname = rname;
		serial = serial;
		refresh = refresh;
		retry = retry;
		expire = expire;
		minimum = minimum;
	}, soa_mt);
end

function parsers.A(packet)
	return t_concat({ c_unpack(">BBBB", packet) }, ".", 1, 4);
end

function parsers.AAAA(packet)
	local t = { c_unpack(">I2I2I2I2I2I2I2I2", packet) };
	for i=1,8 do
		t[i] = ("%x"):format(t[i]); -- skips leading zeros
	end
	local ip = t_concat(t, ":", 1, 8);
	local len = #ip:match("^[0:]*");
	local token;
	for s in ip:gmatch(":[0:]+") do
		if len < #s then len,token = #s,s; end -- find longest sequence of zeros
	end
	return ip:gsub(token or "^[0:]+", "::", 1);
end

local mx_mt = {
	__tostring = function(t)
		return ("%d %s"):format(t.pref, t.mx)
	end
};
function parsers.MX(packet)
	local name = readDnsName(packet, 3);
	local pref = c_unpack(">I2", packet);
	return setmetatable({
		pref = pref;
		mx = name;
	}, mx_mt);
end

local srv_mt = {
	__tostring = function(t)
		return ("%d %d %d %s"):format(t.priority, t.weight, t.port, t.target);
	end
};
function parsers.SRV(packet)
	local name = readDnsName(packet, 7);
	local priority, weight, port = c_unpack(">I2I2I2",packet);
	return setmetatable({
		priority = priority;
		weight   = weight;
		port     = port;
		target   = name;
	}, srv_mt);
end

local txt_mt = { __tostring = t_concat };
function parsers.TXT(packet)
	local r, pos = {}, 1;
	while pos < #packet do
		local s, n = c_unpack(">Bc0", packet, pos);
		t_insert(r, s);
		pos = n;
	end
	return setmetatable(r, txt_mt);
end

local fallback_mt = {
	__tostring = function(t)
		return t.raw:gsub("[^!-~]",function(c)return ("\\%03d"):format(c:byte()) end);
	end;
};
local function fallback_parser(packet)
	return setmetatable({raw=packet},fallback_mt);
end
setmetatable(parsers, { __index = function() return fallback_parser end });

return {
	parsers = parsers,
	classes = classes,
	types = types,
	errors = errors,
};
