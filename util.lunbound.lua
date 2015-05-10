-- libunbound based net.adns replacement for Prosody IM
-- Copyright (C) 2012-2015 Kim Alvefur
--
-- This file is MIT/X11 licensed.

local ffi = require "ffi";
local jit = require "jit";
local char = ffi.new("char *");
local function tochar(s)
	return ffi.cast(char, s);
end
local libunbound = ffi.load"unbound";
-- cpp <<< '#include <unbound.h>' | grep '^[^#]'
ffi.cdef[[
struct ub_ctx;
struct ub_result {
 char* qname;
 int qtype;
 int qclass;
 char** data;
 int* len;
 char* canonname;
 int rcode;
 void* answer_packet;
 int answer_len;
 int havedata;
 int nxdomain;
 int secure;
 int bogus;
 char* why_bogus;
};
typedef void (*ub_callback_t)(void*, int, struct ub_result*);
struct ub_ctx* ub_ctx_create(void);
void ub_ctx_delete(struct ub_ctx* ctx);
int ub_ctx_resolvconf(struct ub_ctx* ctx, char* fname);
int ub_ctx_hosts(struct ub_ctx* ctx, char* fname);
int ub_ctx_add_ta(struct ub_ctx* ctx, char* ta);
int ub_ctx_async(struct ub_ctx* ctx, int dothread);
int ub_poll(struct ub_ctx* ctx);
int ub_wait(struct ub_ctx* ctx);
int ub_fd(struct ub_ctx* ctx);
int ub_process(struct ub_ctx* ctx);
int ub_resolve(struct ub_ctx* ctx, char* name, int rrtype,
 int rrclass, struct ub_result** result);
int ub_resolve_async(struct ub_ctx* ctx, char* name, int rrtype,
 int rrclass, void* mydata, ub_callback_t callback, int* async_id);
int ub_cancel(struct ub_ctx* ctx, int async_id);
void ub_resolve_free(struct ub_result* result);
const char* ub_strerror(int err);
const char* ub_version(void);
]];
local unbound = { _LIBVER = ffi.string(libunbound.ub_version()), _LIB = libunbound };
local context = {};
local context_mt = { __index = context, __gc = libunbound.ub_ctx_delete };

context.add_ta = libunbound.ub_ctx_add_ta;
context.async = libunbound.ub_ctx_async;
context.cancel = libunbound.ub_cancel;
context.getfd = libunbound.ub_fd;
context.hosts = libunbound.ub_ctx_hosts;
context._process = libunbound.ub_process;
context.resolvconf = libunbound.ub_ctx_resolvconf;
context._resolve = libunbound.ub_resolve;
context._resolve_async = libunbound.ub_resolve_async;

unbound.config = {
	resolvconf = true;
	async = true;
	trusted = ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5";
	hoststxt = true;
}

local function parse_result(err, result)
	ffi.gc(result, libunbound.ub_resolve_free);
	local answer;
	if err == 0 and result[0].havedata then
		answer = {
			qname  = ffi.string(result[0].qname);
			qtype  = result[0].qtype;
			qclass = result[0].qclass;
			rcode  = result[0].rcode;
			secure = result[0].secure == 1;
			bogus  = result[0].bogus == 1 and ffi.string(result[0].why_bogus) or nil;
		}
		if result[0].canonname ~= nil then
			answer.canonname = ffi.string(result[0].canonname)
		end
		local i, data = 0;
		while result[0].len[i] > 0 do
			data = ffi.string(result[0].data[i], result[0].len[i]);
			i = i + 1; answer[i]  = data;
		end
		return answer;
	end
	return nil, ffi.string(libunbound.ub_strerror(err));
end

function unbound.new(config)
	local ub_ctx = libunbound.ub_ctx_create();
	config = config or unbound.config;

	if config.async ~= nil then
		ub_ctx:async(config.async);
	end

	if config.resolvconf == true then
		ub_ctx:resolvconf(nil);
	else
		ub_ctx:resolvconf(tochar(config.resolvconf));
	end

	if config.hoststxt == true then
		ub_ctx:hosts(nil);
	else
		ub_ctx:hosts(tochar(config.hoststxt));
	end

	if config.trusted then
		if type(config.trusted) == "string" then
			ub_ctx:add_ta(tochar(config.trusted));
		elseif type(config.trusted) == "table" then
			for i=1,#config.trusted do
				ub_ctx:add_ta(tochar(config.trusted[i]));
			end
		end
	end

	return ub_ctx;
end

function context:resolve(name, rrtype, rrclass)
	local result = ffi.new("struct ub_result*");
	local ok = self:_resolve(tochar(name), rrtype, rrclass, result);
	return parse_result(ok, result);
end

function context:resolve_async(callback, name, rrtype, rrclass)
	local query_id = ffi.new("int[1]");
	local function l_callback(t, err, result)
		ffi.cast("ub_callback_t", t):free();
		callback(parse_result(err, result));
	end
	local ub_callback_t = ffi.cast("ub_callback_t", l_callback);
	local	ok = self:_resolve_async(tochar(name), rrtype, rrclass, ub_callback_t, ub_callback_t, query_id);
	if ok ~= 0 then
		return nil, ffi.string(libunbound.ub_strerror(ok));
	end
	return query_id[0];
end

function context:process()
	self:_process();
end
jit.off(context.process)

unbound.ub_ctx = ffi.metatype("struct ub_ctx", context_mt);

return unbound;
