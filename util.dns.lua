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
local s_byte = string.byte;
local s_format = string.format;
local s_gsub = string.gsub;
local s_sub = string.sub;
local s_match = string.match;
local s_gmatch = string.gmatch;
local has_struct, c_unpack = pcall(require, "struct");
if has_struct then c_unpack = c_unpack.unpack; end

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

local errors = {};
do
local _errors = {
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
for i=0,#_errors do
	local short, long = _errors[i][1], _errors[i][2];
	errors[i] = short;
	errors[short] = long;
end
end

-- Simplified versions of Waqas DNS parsers
-- Only the per RR parsers are needed and only feed a single RR

local parsers = {};

-- No support for pointers, but libunbound appears to take care of that.
local function readDnsName(packet, pos)
	local pack_len = #packet;
	local r, pos = {}, pos or 1;
	repeat
		local len = s_byte(packet, pos) or 0;
		t_insert(r, s_sub(packet, pos + 1, pos + len));
		pos = pos + len + 1;
	until len == 0 or pos >= pack_len;
	return t_concat(r, "."), pos;
end

-- These are just simple names.
parsers.CNAME = readDnsName;
parsers.NS = readDnsName
parsers.PTR = readDnsName;

local soa_mt = {
	__tostring = function(t)
		return s_format("%s %s %d %d %d %d %d", t.mname, t.rname, t.serial, t.refresh, t.retry, t.expire, t.minimum);
	end
};
function parsers.SOA(packet)
	local mname, offset = readDnsName(packet, 1);
	local rname, offset = readDnsName(packet, offset);
	local a,b,c,d;
	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	local serial  = a*0x1000000 + b*0x10000 + c*0x100 + d;
	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	local refresh = a*0x1000000 + b*0x10000 + c*0x100 + d;
	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	local retry   = a*0x1000000 + b*0x10000 + c*0x100 + d;
	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	local expire  = a*0x1000000 + b*0x10000 + c*0x100 + d;
	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	local minimum = a*0x1000000 + b*0x10000 + c*0x100 + d;
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
	local a,b,c,d = s_byte(packet, 1, 4);
	return a.."."..b.."."..c.."."..d;
end

function parsers.AAAA(packet)
		local t = { nil, nil, nil, nil, nil, nil, nil, nil, };
		for i=1,8 do
			local hi, lo = s_byte(packet, i*2-1, i*2);
			t[i] = s_format("%x", hi*256+lo); -- skips leading zeros
		end
		local ip = t_concat(t, ":", 1, 8);
		local len = #s_match(ip, "^[0:]*");
		local token;
		for s in s_gmatch(ip, ":[0:]+") do
			if len < #s then len,token = #s,s; end -- find longest sequence of zeros
		end
		return s_gsub(ip, token or "^[0:]+", "::", 1);
end

local mx_mt = {
	__tostring = function(t)
		return s_format("%d %s", t.pref, t.mx)
	end
};
function parsers.MX(packet)
	local name = readDnsName(packet, 3);
	local b1,b2 = s_byte(packet, 1, 2);
	return setmetatable({
		pref = b1*256+b2;
		mx = name;
	}, mx_mt);
end

local srv_mt = {
	__tostring = function(t)
		return s_format("%d %d %d %s", t.priority, t.weight, t.port, t.target);
	end
};
function parsers.SRV(packet)
	local name = readDnsName(packet, 7);
	local b1,b2,b3,b4,b5,b6 = s_byte(packet, 1, 6);
	return setmetatable({
		priority = b1*256+b2;
		weight   = b3*256+b4;
		port     = b5*256+b6;
		target   = name;
	}, srv_mt);
end

local txt_mt = { __tostring = t_concat };
function parsers.TXT(packet, pos)
	local pack_len = #packet;
	local r, pos = {}, 1;
	repeat
		local len = s_byte(packet, pos) or 0;
		t_insert(r, s_sub(packet, pos + 1, pos + len));
		pos = pos + len + 1;
	until pos >= pack_len;
	return setmetatable(r, txt_mt);
end

local tohex = function(c) return s_format("%02X", s_byte(c)) end
local tlsa_usages = {
	[0] = "CA constraint",
	"service certificate constraint",
	"trust anchor assertion",
	"domain-issued certificate",
};
local tlsa_selectors = { [0] = "full", "SubjectPublicKeyInfo" };
local tlsa_match_types = { [0] = "exact", "SHA-256", "SHA-512" };
local tlsa_mt = {
	__tostring = function(t)
		return s_format("%d %d %d %s", t.use, t.select, t.match, s_gsub(t.data, ".", tohex));
	end;
	__index = {
		getUsage = function(t) return tlsa_usages[t.use] end;
		getSelector = function(t) return tlsa_selectors[t.select] end;
		getMatchType = function(t) return tlsa_match_types[t.match] end;
	}
};
function parsers.TLSA(packet)
	local use, select, match = s_byte(packet, 1,3);
	return setmetatable({
		use = use;
		select = select;
		match = match;
		data = s_sub(packet, 4);
	}, tlsa_mt);
end


local fallback_mt = {
	__tostring = function(t)
		return = s_format([[\# %d %s]], #t.raw, s_gsub(t.raw, ".", tohex));
	end;
};
local function fallback_parser(packet)
	return setmetatable({ raw = packet },fallback_mt);
end
setmetatable(parsers, { __index = function() return fallback_parser end });

return {
	parsers = parsers,
	classes = classes,
	types = types,
	errors = errors,
};
