/* Copyright (C) 2014-2015 - Kim Alvefur
 *
 * This file is MIT/X11 licensed.
 */

#include <lualib.h>
#include <lauxlib.h>
#include <unbound.h>

#ifndef NO_ROOT_TA
#include "iana_root_ta.h"
#endif

typedef struct {
	struct lua_State* L;
	int async_id;
} cb_data;

/*
 * Create a new context.
 * Takes an optional single table with options as argument.
 */
int lub_new(lua_State* L) {
	int ret;
	int i = 1;
	struct ub_ctx** ctx;

	/* Load table with default config if none given. */
	if(lua_isnoneornil(L, 1)) {
		lua_settop(L, 0);
		luaL_getmetatable(L, "ub_default_config");
	} else {
		luaL_checktype(L, 1, LUA_TTABLE);
		lua_settop(L, 1);
	}

	/* Make sure there is room for 4 items on the stack */
	luaL_checkstack(L, 3, NULL);

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

/*
 * Get FD to watch in for readability in your event loop
 */
static int lub_ctx_getfd(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	lua_pushinteger(L, ub_fd(*ctx));
	return 1;
}

/*
 * Turns ub_result into table
 */
static int lub_parse_result(lua_State* L, struct ub_result* result) {
	int i = 0;

	luaL_checkstack(L, 2, NULL);

	lua_createtable(L, 8, 10);

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

/*
 * Perform an synchronous lookup
 */
static int lub_resolve(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	struct ub_result* result;
	char* qname = (char*)luaL_checkstring(L, 2);
	int rrtype = luaL_optinteger(L, 3, 1);
	int rrclass = luaL_optinteger(L, 4, 1);
	int ret = ub_resolve(*ctx, qname, rrtype, rrclass, &result);

	if(ret != 0) {
		lua_pushnil(L);
		lua_pushstring(L, ub_strerror(ret));
		return 2;
	}

	return lub_parse_result(L, result);
}

/*
 * Callback for async queries
 */
void lub_callback(void* data, int err, struct ub_result* result) {
	cb_data* my_data = (cb_data*)data;
	lua_State* L = my_data->L;

	/* remove query and callback from registry */
	luaL_getmetatable(L, "ub_queries");
	lua_pushnil(L);
	lua_rawseti(L, -2, my_data->async_id); /* ub_queries[async_id] = nil */
	lua_pop(L, 1);

	luaL_getmetatable(L, "ub_cb");
	lua_rawgeti(L, -1, my_data->async_id);
	lua_pushnil(L);
	lua_rawseti(L, -3, my_data->async_id); /* ub_cb[async_id] = nil */

	if(err != 0) {
		lua_pushnil(L);
		lua_pushstring(L, ub_strerror(err));
	} else {
		lub_parse_result(L, result);
	}

	if(lua_pcall(L, err == 0 ? 1 : 2, 0, 0) != 0) {
		lua_pop(L, 1); /* Ignore error */
	}

	lua_pop(L, 1); /* ub_cb */
}

/*
 * Start an asynchronous lookup
 */
static int lub_resolve_async(lua_State* L) {
	int ret, rrtype, rrclass;
	char* qname;
	cb_data* my_data;
	struct ub_ctx** ctx;

	/* ub_ctx:resolve_async(callback, "example.net", rrtype, rrclass) */
	ctx = luaL_checkudata(L, 1, "ub_ctx");
	luaL_checktype(L, 2, LUA_TFUNCTION);
	qname = (char*)luaL_checkstring(L, 3);
	rrtype = luaL_optinteger(L, 4, 1);
	rrclass = luaL_optinteger(L, 5, 1);

	lua_settop(L, 2);

	/* Structure with reference to Lua state */
	my_data = (cb_data*)lua_newuserdata(L, sizeof(cb_data));
	my_data->L = L;

	ret = ub_resolve_async(*ctx, qname, rrtype, rrclass, my_data, lub_callback, &my_data->async_id);

	if(ret != 0) {
		lua_pushnil(L);
		lua_pushstring(L, ub_strerror(ret));
		return 2;
	}

	luaL_getmetatable(L, "ub_queries");
	lua_pushvalue(L, 3); /* the cb_data userdata */
	lua_rawseti(L, 4, my_data->async_id); /* ub_queries[async_id] = cb_data */
	lua_pop(L, 1);

	luaL_getmetatable(L, "ub_cb"); /* Get the callback registry */
	lua_pushvalue(L, 2); /* the callback */
	lua_rawseti(L, 4, my_data->async_id); /* ub_queries[async_id] = cb_data */
	lua_pop(L, 1);

	lua_pushinteger(L, my_data->async_id);
	return 1;
}

/*
 * Cancel a query using the id returned from resolve_async
 */
static int lub_cancel(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	int async_id = luaL_checkinteger(L, 2);
	int ret = ub_cancel(*ctx, async_id);

	if(ret != 0) {
		lua_pushnil(L);
		lua_pushstring(L, ub_strerror(ret));
		return 2;
	}

	luaL_getmetatable(L, "ub_queries");
	lua_pushnil(L);
	lua_rawseti(L, -2, async_id); /* ub_queries[async_id] = nil */
	lua_pop(L, 1);

	luaL_getmetatable(L, "ub_cb"); /* Get the callback registry */
	lua_pushnil(L);
	lua_rawseti(L, -2, async_id); /* ub_cb[async_id] = nil */
	lua_pop(L, 1);

	lua_pushboolean(L, 1);
	return 1;
}

/*
 * Process all completed queries and call their callbacks
 */
static int lub_process(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	lua_settop(L, 1);
	ub_process(*ctx);
	return 0;
}

/*
 * Wait for all queries to complete and call all callbacks
 */
static int lub_wait(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	ub_wait(*ctx);
	return 0;
}

/*
 * Check if context has new results to process
 */
static int lub_poll(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	lua_pushboolean(L, ub_poll(*ctx));
	return 1;
}

/*
 * Context metatable
 */
static luaL_Reg ctx_mt[] = {
	{"__gc", lub_ctx_destroy},
	{"__tostring", lub_ctx_tostring},
	{NULL, NULL}
};

/*
 * Context methods
 */
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

/*
 * Exported module functions
 */
static luaL_Reg lub_lib_funcs[] = {
	{"new", lub_new},
	{NULL, NULL}
};

#if (LUA_VERSION_NUM == 501)
#define luaL_setfuncs(L, R, N) luaL_register(L, NULL, R)
#endif

int luaopen_lunbound(lua_State* L) {

	/* Metatable for contexts */
	luaL_newmetatable(L, "ub_ctx");
	luaL_setfuncs(L, ctx_mt, 0);
	lua_createtable(L, 0, 2);
	luaL_setfuncs(L, ctx_methods, 0);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	/* Table to keep callbacks in */
	luaL_newmetatable(L, "ub_cb");
	lua_pop(L, 1);

	/* Table to keep map of async_id to callbacks */
	luaL_newmetatable(L, "ub_queries");
	lua_pop(L, 1);

	/* Main module table */
	lua_createtable(L, 0, 1);
	luaL_setfuncs(L, lub_lib_funcs, 0);
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
#ifdef IANA_ROOT_TA
	/* Hardcoded root */
	lua_pushstring(L, IANA_ROOT_TA);
	lua_setfield(L, -2, "trusted");
#endif

	lua_setfield(L, -2, "config");

	return 1;
}

int luaopen_util_lunbound(lua_State* L) {
	return luaopen_lunbound(L);
}
