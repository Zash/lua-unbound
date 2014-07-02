/* Copyright (C) 2014 - Kim Alvefur
 *
 * This file is MIT/X11 licensed.
 */

#include <lualib.h>
#include <lauxlib.h>
#include <unbound.h>

/* Hardcoded root trust anchor ... I know
 * https://data.iana.org/root-anchors/root-anchors.xml
 */
#define IANA_ROOT_TA ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"

typedef struct {
	struct lua_State* L;
	int func_ref;
	int self_ref;
} cb_data;

int lub_new(lua_State* L) {
	int ret;
	int i = 1;
	struct ub_ctx** ctx;

	/* Load table with default config if none given. */
	if(lua_isnoneornil(L, 1)) {
		lua_settop(L, 0);
		luaL_getmetatable(L, "ub_default_config");
	} else {
		lua_settop(L, 1);
		luaL_checktype(L, 1, LUA_TTABLE);
	}

	/* Create context and assign metatable. */
	ctx = lua_newuserdata(L, sizeof(struct ub_ctx*));
	*ctx = ub_ctx_create();
	luaL_getmetatable(L, "ub_ctx");
	lua_setmetatable(L, -2);

	/* Handle config table */

	/* Enable threads?
	 * ["async"] = true  -- threads
	 *           = false -- fork a process
	 */
	lua_getfield(L, 1, "async");
	ret = ub_ctx_async(*ctx, lua_isboolean(L, -1) ? lua_toboolean(L, -1) : 1);
	luaL_argcheck(L, ret == 0, 1, ub_strerror(ret));
	lua_pop(L, 1);

	/* Path to resolv.conf
	 * ["resolvconf"] = "/path/to/resolv.conf"
	 *                = true  -- Use resolvers set by OS
	 *                = false -- Use root hints
	 */
	lua_getfield(L, 1, "resolvconf");

	if(lua_isstring(L, -1)) {
		ret = ub_ctx_resolvconf(*ctx, (char*)lua_tostring(L, -1));
	} else if(lua_isboolean(L, -1) && lua_toboolean(L, -1)) {
		ret = ub_ctx_resolvconf(*ctx, NULL);
	}

	/* else use root hits */
	luaL_argcheck(L, ret == 0, 1, ub_strerror(ret));
	lua_pop(L, 1);

	/* Path to hosts.txt
	 * ["hoststxt"] = "/path/to/hosts.txt"
	 *              = true  -- Use appropriate hosts.txt depending on OS
	 */
	lua_getfield(L, 1, "hoststxt");

	if(lua_isstring(L, -1)) {
		ret = ub_ctx_hosts(*ctx, (char*)lua_tostring(L, -1));
	} else if(lua_isboolean(L, -1) && lua_toboolean(L, -1)) {
		ret = ub_ctx_hosts(*ctx, NULL);
	}

	luaL_argcheck(L, ret == 0, 1, ub_strerror(ret));
	lua_pop(L, 1);

	/* List of trust anchors
	 * ["trusted"] = ". IN DS ..." -- Single string or array of strings
	 */
	lua_getfield(L, 1, "trusted");

	if(lua_istable(L, -1)) {
		lua_rawgeti(L, -1, i++);

		while(ret == 0 && lua_isstring(L, -1)) {
			ret = ub_ctx_add_ta(*ctx, (char*)lua_tostring(L, -1));
			lua_pop(L, 1);
			lua_rawgeti(L, -1, i++);
		}

		lua_pop(L, 1);
		luaL_argcheck(L, ret == 0, 1, ub_strerror(ret));
	} else if(lua_isstring(L, -1)) {
		ret = ub_ctx_add_ta(*ctx, (char*)lua_tostring(L, -1));
	} else if(!lua_isnil(L, -1)) {
		luaL_argerror(L, 1, "'trust' must be string or array");
	}

	luaL_argcheck(L, ret == 0, 1, ub_strerror(ret));

	lua_pop(L, 1);

	return 1;
}

static int lub_ctx_destroy(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	ub_ctx_delete(*ctx);
	return 0;
}

static int lub_ctx_tostring(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	lua_pushfstring(L, "ub_ctx: %p", ctx);
	return 1;
}

static int lub_ctx_getfd(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	lua_pushinteger(L, ub_fd(*ctx));
	return 1;
}

/* Turns ub_result into table */
static int lub_parse_result(lua_State* L, struct ub_result* result) {
	int i = 0;

	lua_createtable(L, 10, 12);

	lua_pushstring(L, result->qname);
	lua_setfield(L, -2, "qname");

	lua_pushinteger(L, result->qtype);
	lua_setfield(L, -2, "qtype");

	lua_pushinteger(L, result->qclass);
	lua_setfield(L, -2, "qclass");

	lua_pushboolean(L, result->havedata);
	lua_setfield(L, -2, "havedata");

	if(result->canonname) {
		lua_pushstring(L, result->canonname);
		lua_setfield(L, -2, "canonname");
	}

	lua_pushboolean(L, result->nxdomain);
	lua_setfield(L, -2, "nxdomain");

	/* Security status */
	lua_pushboolean(L, result->secure);
	lua_setfield(L, -2, "secure");

	if(result->bogus) {
		lua_pushstring(L, result->why_bogus);
		lua_setfield(L, -2, "bogus");
	}

	lua_pushinteger(L, result->rcode);
	lua_setfield(L, -2, "rcode");

	if(result->havedata) {
		while(result->len[i] > 0) {
			lua_pushlstring(L, result->data[i], result->len[i]);
			lua_rawseti(L, -2, ++i);
		}
	}

	lua_pushinteger(L, i);
	lua_setfield(L, -2, "n");

	ub_resolve_free(result);
	return 1;
}

static int lub_resolve(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	struct ub_result* result;
	char* qname = (char*)luaL_checkstring(L, 2);
	int rrtype = luaL_optint(L, 3, 1);
	int rrclass = luaL_optint(L, 4, 1);
	int ret = ub_resolve(*ctx, qname, rrtype, rrclass, &result);

	if(ret != 0) {
		lua_pushnil(L);
		lua_pushstring(L, ub_strerror(ret));
		return 2;
	}

	return lub_parse_result(L, result);
}

void lub_callback(void* data, int err, struct ub_result* result) {
	cb_data* my_data = (cb_data*)data;
	lua_State* L = my_data->L;
	luaL_getmetatable(L, "ub_cb");
	lua_rawgeti(L, -1, my_data->func_ref);

	if(err != 0) {
		lua_pushnil(L);
	} else {
		lub_parse_result(L, result);
	}

	lua_pushstring(L, ub_strerror(err));

	if(lua_pcall(L, 2, 0, 0) != 0) {
		lua_pop(L, 1); /* Ignore error */
	}

	luaL_unref(L, -1, my_data->func_ref);
	luaL_unref(L, -1, my_data->self_ref);
	lua_settop(L, 1);
}

static int lub_resolve_async(lua_State* L) {
	int ref, ret, async_id;
	cb_data* my_data;
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	char* qname = (char*)luaL_checkstring(L, 3);
	int rrtype = luaL_optint(L, 4, 1);
	int rrclass = luaL_optint(L, 5, 1);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	luaL_getmetatable(L, "ub_cb");
	my_data = (cb_data*)lua_newuserdata(L, sizeof(cb_data));
	my_data->L = L;
	my_data->self_ref = luaL_ref(L, -2);
	lua_pushvalue(L, 2);
	ref = luaL_ref(L, -2);
	lua_rawgeti(L, -1, ref);
	my_data->func_ref = ref;
	lua_pop(L, 1);
	ret = ub_resolve_async(*ctx, qname, rrtype, rrclass, my_data, lub_callback, &async_id);

	if(ret != 0) {
		luaL_unref(L, -1, my_data->func_ref);
		luaL_unref(L, -1, my_data->self_ref);
		lua_pushnil(L);
		lua_pushstring(L, ub_strerror(ret));
		return 2;
	}

	lua_pushinteger(L, async_id);
	return 1;
}

static int lub_cancel(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	int async_id = luaL_checkint(L, 2);
	int ret = ub_cancel(*ctx, async_id);

	if(ret != 0) {
		lua_pushnil(L);
		lua_pushstring(L, ub_strerror(ret));
		return 2;
	}

	lua_pushinteger(L, async_id);
	return 1;
}

static int lub_process(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	lua_checkstack(L, 10);
	ub_process(*ctx);
	return 0;
}

static int lub_wait(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	ub_wait(*ctx);
	return 0;
}

static int lub_poll(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	lua_pushboolean(L, ub_poll(*ctx));
	return 1;
}

static luaL_Reg ctx_mt[] = {
	{"__gc", lub_ctx_destroy},
	{"__tostring", lub_ctx_tostring},
	{NULL, NULL}
};

static luaL_Reg ctx_methods[] = {
	{"getfd", lub_ctx_getfd},
	{"resolve", lub_resolve},
	{"resolve_async", lub_resolve_async},
	{"cancel", lub_cancel},
	{"process", lub_process},
	{"wait", lub_wait},
	{"poll", lub_poll},
	{NULL, NULL}
};

static luaL_Reg lub_lib_funcs[] = {
	{"new", lub_new},
	{NULL, NULL}
};

#if (LUA_VERSION_NUM == 502)
#define luaL_register(L, N, R) luaL_setfuncs(L, R, 0)
#endif

int luaopen_lunbound(lua_State* L) {

	luaL_newmetatable(L, "ub_ctx");
	luaL_register(L, NULL, ctx_mt);
	lua_createtable(L, 0, 2);
	luaL_register(L, NULL, ctx_methods);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luaL_newmetatable(L, "ub_cb");
	lua_pop(L, 1);

	lua_createtable(L, 0, 1);
	luaL_register(L, NULL, lub_lib_funcs);
	lua_pushstring(L, ub_version());
	lua_setfield(L, -2, "_LIBVER");

	/* Defaults */
	luaL_newmetatable(L, "ub_default_config");
	/* Threads enabled */
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "async");
	/* Use system resolv.conf */
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "resolvconf");
	/* Use system hosts.txt */
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "hoststxt");
	/* Hardcoded root */
	lua_pushstring(L, IANA_ROOT_TA);
	lua_setfield(L, -2, "trusted");

	lua_setfield(L, -2, "config");

	return 1;
}

int luaopen_util_lunbound(lua_State* L) {
	return luaopen_lunbound(L);
}
