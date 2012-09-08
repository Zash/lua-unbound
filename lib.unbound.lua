local ffi = require "ffi";
local unbound = ffi.load"unbound";
-- libunbound headers
-- https://unbound.net/
-- This file has been preprocessed, as ffi.cdef() doesn't do this
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
int ub_resolve(struct ub_ctx* ctx, char* name, int rrtype, int rrclass, struct ub_result** result);
int ub_resolve_async(struct ub_ctx* ctx, char* name, int rrtype, int rrclass, void* mydata, ub_callback_t callback, int* async_id);
int ub_cancel(struct ub_ctx* ctx, int async_id);
void ub_resolve_free(struct ub_result* result);
const char* ub_strerror(int err);
int ub_ctx_print_local_zones(struct ub_ctx* ctx);
int ub_ctx_zone_add(struct ub_ctx* ctx, char *zone_name, char *zone_type);
int ub_ctx_zone_remove(struct ub_ctx* ctx, char *zone_name);
int ub_ctx_data_add(struct ub_ctx* ctx, char *data);
int ub_ctx_data_remove(struct ub_ctx* ctx, char *data);
]]

return unbound
