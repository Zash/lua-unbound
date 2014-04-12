-- libunbound based net.adns replacement for Prosody IM
-- Copyright (C) 2012-2014 Kim Alvefur
-- Copyright (C) 2012 Waqas Hussain
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

-- Converted from
-- http://www.iana.org/assignments/dns-parameters
-- 2014-03-13

local classes = {
	IN = 1; "IN";
	nil;
	CH = 3; "CH";
	HS = 4; "HS";
};

local types = { "A"; "NS"; "MD"; "MF"; "CNAME"; "SOA"; "MB"; "MG"; "MR";
"NULL"; "WKS"; "PTR"; "HINFO"; "MINFO"; "MX"; "TXT"; "RP"; "AFSDB";
"X25"; "ISDN"; "RT"; "NSAP"; "NSAP-PTR"; "SIG"; "KEY"; "PX"; "GPOS";
"AAAA"; "LOC"; "NXT"; "EID"; "NIMLOC"; "SRV"; "ATMA"; "NAPTR"; "KX";
"CERT"; "A6"; "DNAME"; "SINK"; "OPT"; "APL"; "DS"; "SSHFP"; "IPSECKEY";
"RRSIG"; "NSEC"; "DNSKEY"; "DHCID"; "NSEC3"; "NSEC3PARAM"; "TLSA";
[55]="HIP"; [56]="NINFO"; [57]="RKEY"; [58]="TALINK"; [59]="CDS";
TLSA=52; NS=2; [249]="TKEY"; [251]="IXFR"; NSAP=22; UID=101; APL=42;
MG=8; NIMLOC=32; DHCID=49; TALINK=58; HINFO=13; MINFO=14; EID=31; DS=43;
EUI48=108; RKEY=57; TKEY=249; NID=104; NAPTR=35; RT=21; LP=107; L32=105;
KEY=25; MD=3; MX=15; A6=38; KX=36; PX=26; CAA=257; WKS=11; TSIG=250;
MAILA=254; CDS=59; SINK=40; LOC=29; DLV=32769; [32769]="DLV"; IXFR=251; 
TA=32768; [32768]="TA"; [250]="TSIG"; [252]="AXFR"; NSEC=47; HIP=55; 
UNSPEC=103; [256]="URI"; NSEC3PARAM=51; ["*"]=255; URI=256; [255]="*"; 
[254]="MAILA"; MAILB=253; NXT=30; [253]="MAILB"; AXFR=252; L64=106; 
AFSDB=18; ISDN=20; NINFO=56; SRV=33; DNSKEY=48; X25=19; TXT=16; RRSIG=46; 
SPF=99; DNAME=39; CNAME=5; EUI64=109; A=1; MR=9; IPSECKEY=45; OPT=41; 
UINFO=100; ["NSAP-PTR"]=23; GID=102; [257]="CAA"; [103]="UNSPEC"; 
[99]="SPF"; MF=4; [101]="UID"; [102]="GID"; SOA=6; [104]="NID"; 
[105]="L32"; [106]="L64"; [107]="LP"; [108]="EUI48"; [109]="EUI64"; 
NSEC3=50; RP=17; PTR=12; [100]="UINFO"; NULL=10; AAAA=28; MB=7; GPOS=27; 
SSHFP=44; CERT=37; SIG=24; ATMA=34; };

local errors = {
	NoError = "No Error"; [0] = "NoError";
	FormErr = "Format Error"; "FormErr";
	ServFail = "Server Failure"; "ServFail";
	NXDomain = "Non-Existent Domain"; "NXDomain";
	NotImp = "Not Implemented"; "NotImp";
	Refused = "Query Refused"; "Refused";
	YXDomain = "Name Exists when it should not"; "YXDomain";
	YXRRSet = "RR Set Exists when it should not"; "YXRRSet";
	NXRRSet = "RR Set that should exist does not"; "NXRRSet";
	NotAuth = "Server Not Authoritative for zone"; "NotAuth";
	NotZone = "Name not contained in zone"; "NotZone";
};

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
	local mname, rname, serial, refresh, retry, expire, minimum, offset, a,b,c,d;

	mname, offset = readDnsName(packet, 1);
	rname, offset = readDnsName(packet, offset);

	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	serial  = a*0x1000000 + b*0x10000 + c*0x100 + d;

	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	refresh = a*0x1000000 + b*0x10000 + c*0x100 + d;

	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	retry   = a*0x1000000 + b*0x10000 + c*0x100 + d;

	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	expire  = a*0x1000000 + b*0x10000 + c*0x100 + d;

	a,b,c,d = s_byte(packet, offset, offset+3); offset = offset + 4;
	minimum = a*0x1000000 + b*0x10000 + c*0x100 + d;

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
	[0] = "PKIX-CA",
	[1] = "PKIX-EE",
	[2] = "DANE-TA",
	[3] = "DANE-EE",
	[255] = "PrivCert",
};
local tlsa_selectors = {
	[0] = "Cert",
	[1] = "SPKI",
	[255] = "PrivSel",
};
local tlsa_match_types = {
	[0] = "Full",
	[1] = "SHA2-256",
	[2] = "SHA2-512",
	[255] = "PrivMatch",
};
local tlsa_mt = {
	__tostring = function(t)
		return s_format("%s %s %s %s", tlsa_usages[t.use] or t.use, tlsa_selectors[t.select] or t.select, tlsa_match_types[t.match] or t.match, s_gsub(t.data, ".", tohex));
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

local params = {
	TLSA = {
		use = tlsa_usages;
		select = tlsa_selectors;
		match = tlsa_match_types;
	};
};

local fallback_mt = {
	__tostring = function(t)
		return s_format([[\# %d %s]], #t.raw, s_gsub(t.raw, ".", tohex));
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
	params = params,
};
