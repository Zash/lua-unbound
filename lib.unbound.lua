-- libunbound based net.adns replacement for Prosody IM
-- Copyright (C) 2012-2013 Kim Alvefur
--
-- This file is MIT/X11 licensed.

local setmetatable = setmetatable;
local ffi = require "ffi";
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
int ub_ctx_set_option(struct ub_ctx* ctx, char* opt, char* val);
int ub_ctx_get_option(struct ub_ctx* ctx, char* opt, char** str);
int ub_ctx_config(struct ub_ctx* ctx, char* fname);
int ub_ctx_set_fwd(struct ub_ctx* ctx, char* addr);
int ub_ctx_resolvconf(struct ub_ctx* ctx, char* fname);
int ub_ctx_hosts(struct ub_ctx* ctx, char* fname);
int ub_ctx_add_ta(struct ub_ctx* ctx, char* ta);
int ub_ctx_add_ta_file(struct ub_ctx* ctx, char* fname);
int ub_ctx_trustedkeys(struct ub_ctx* ctx, char* fname);
int ub_ctx_debugout(struct ub_ctx* ctx, void* out);
int ub_ctx_debuglevel(struct ub_ctx* ctx, int d);
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
int ub_ctx_print_local_zones(struct ub_ctx* ctx);
int ub_ctx_zone_add(struct ub_ctx* ctx, char *zone_name, char *zone_type);
int ub_ctx_zone_remove(struct ub_ctx* ctx, char *zone_name);
int ub_ctx_data_add(struct ub_ctx* ctx, char *data);
int ub_ctx_data_remove(struct ub_ctx* ctx, char *data);
const char* ub_version(void);
]];
local unbound = { _LIBVER = ffi.string(libunbound.ub_version()), _LIB = libunbound };
local context = {};
local context_mt = { __index = context };

local function parse_result(err, result)
	local answer;
	if err == 0 and result[0].havedata then
		local result = result[0];
		answer = {
			qname = ffi.string(result.qname),
			qclass = result.qclass,
			qtype = result.qtype;
			rcode = result.rcode;
			secure = result.secure == 1;
			bogus = result.bogus == 1 and ffi.string(result.why_bogus) or nil;
		}
		local i = 0;
		while result.len[i] > 0 do
			local data = ffi.string(result.data[i], result.len[i]);
			i = i + 1;
			answer[i] = data;
		end
	end
	return answer;
end

function unbound.new(config)
	local self = setmetatable(config or {}, context_mt);
	local function callback(_, err, result)
		local answer = parse_result(err, result);
		libunbound.ub_resolve_free(result);
		if answer and self.callback then
			self:callback(answer);
		end
	end
	self._callback = ffi.cast("ub_callback_t", callback);
	-- IIRC there was something about these not being garbagecollected properly

	self._ctx = ffi.gc(libunbound.ub_ctx_create(), libunbound.ub_ctx_delete);

	if self.async ~= nil then
		libunbound.ub_ctx_async(self._ctx, self.async);
	end
	if self.resolvconf then
		libunbound.ub_ctx_resolvconf(self._ctx, tochar(self.resolvconf));
	end
	if self.hoststxt then
		libunbound.ub_ctx_hosts(self._ctx, tochar(self.hoststxt));
	end
	if self.trusted then
		for i=1,#self.trusted do
			libunbound.ub_ctx_add_ta(self._ctx, tochar(self.trusted[i]));
		end
	end
end

function context:getfd()
	return libunbound.ub_fd(self._ctx);
end

local query = { };
local query_mt = { __index = query };

function query:cancel()
	libunbound.ub_cancel(self._ctx, self.id);
end

local query_id = ffi.new("int[1]");
function context:lookup(n, t, c)
	-- int ub_resolve_async(struct ub_ctx* ctx, char* name, int rrtype, int rrclass, void* mydata, ub_callback_t callback, int* async_id);
	local ok = libunbound.ub_resolve_async(self._ctx, tochar(n), t, c, nil, self._callback, query_id);
	if ok ~= 0 then
		return nil, ffi.string(libunbound.ub_strerror(ok));
	end
	return setmetatable({
		_ctx = self._ctx;
		qname = n;
		qtype = t;
		qclass = c;
		id = query_id[0];
	}, query_mt);
end

function context:process()
	libunbound.ub_process(self._ctx);
end
jit.off(context.process)

return unbound;
