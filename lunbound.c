#include <lualib.h>
#include <lauxlib.h>
#include <unbound.h>

typedef struct {
	struct lua_State* L;
	int func_ref;
} cb_data;

int lub_new(lua_State* L) {
	struct ub_ctx** ctx = lua_newuserdata(L, sizeof(struct ub_ctx*));
	*ctx = ub_ctx_create();
	/* TODO Settings, read from table passed to new() */
	ub_ctx_resolvconf(*ctx, NULL);
	ub_ctx_async(*ctx, 1);
	ub_ctx_add_ta(*ctx, ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"); /* I know ... */
	luaL_getmetatable(L, "ub_ctx");
	lua_setmetatable(L, -2);
	return 1;
}

static int lub_ctx_destroy(lua_State* L) {
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	ub_ctx_delete(*ctx);
	return 0;
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

	while(result->len[i] > 0) {
		lua_pushlstring(L, result->data[i], result->len[i]);
		lua_rawseti(L, -2, ++i);
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
	}
	return lub_parse_result(L, result);
}

void lub_callback(void* data, int err, struct ub_result* result) {
	cb_data* my_data = (cb_data*)data;
	luaL_getmetatable(my_data->L, "ub_cb");
	lua_rawgeti(my_data->L, -1, my_data->func_ref);
	if(lua_type(my_data->L, -1) != LUA_TFUNCTION) {
		/* Unpossible */
		ub_resolve_free(result);
	} else if(err != 0) {
		lua_pushnil(my_data->L);
		lua_pushstring(my_data->L, ub_strerror(err));
		ub_resolve_free(result);
		lua_pcall(my_data->L, 2, 0, 0);
	} else  {
		lub_parse_result(my_data->L, result);
		lua_pcall(my_data->L, 1, 0, 0);
	}
	luaL_unref(my_data->L, -1, my_data->func_ref);
}

static int lub_resolve_async(lua_State* L) {
	int ref, ret, async_id;
	cb_data* my_data;
	struct ub_ctx** ctx = luaL_checkudata(L, 1, "ub_ctx");
	luaL_checktype(L, 2, LUA_TFUNCTION);
	char* qname = (char*)luaL_checkstring(L, 3);
	int rrtype = luaL_optint(L, 4, 1);
	int rrclass = luaL_optint(L, 5, 1);
	my_data = (cb_data*)lua_newuserdata(L, sizeof(cb_data));
	my_data->L = L;
	luaL_getmetatable(L, "ub_cb");
	lua_pushvalue(L, 2);
	ref = luaL_ref(L, -2);
	lua_rawgeti(L, -1, ref);
	my_data->func_ref = ref;
	ret = ub_resolve_async(*ctx, qname, rrtype, rrclass, my_data, lub_callback, &async_id);

	if(ret != 0) {
		lua_pushnil(L);
		lua_pushstring(L, ub_strerror(ret));
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
	{NULL, NULL}
};

static luaL_Reg ctx_methods[] = {
	{"getfd", lub_ctx_getfd},
	{"resolve", lub_resolve},
	{"resolve_async", lub_resolve_async},
	{"process", lub_process},
	{"wait", lub_wait},
	{"poll", lub_poll},
	{NULL, NULL}
};

/*
static luaL_Reg lookup_mt[] = {
	{"__gc", lub_lookup_cancel},
	{NULL, NULL}
};

static luaL_Reg lookup_methods[] = {
	{"cancel", lub_lookup_cancel},
	{NULL, NULL}
};
*/

static luaL_Reg lub_lib_funcs[] = {
	{"new", lub_new},
	{NULL, NULL}
};

int luaopen_lunbound(lua_State* L) {

	luaL_newmetatable(L, "ub_ctx");
	luaL_register(L, NULL, ctx_mt);
	lua_pushstring(L, "__index");
	lua_createtable(L, 0, 2);
	luaL_register(L, NULL, ctx_methods);
	lua_settable(L, 2);
	lua_pop(L, 1);

	/* TODO Return lookup object with cancel method
	luaL_newmetatable(L, "ub_lookup");
	luaL_register(L, NULL, lookup_mt);
	lua_pushstring(L, "__index");
	lua_createtable(L, 0, 2);
	luaL_register(L, NULL, lookup_methods);
	lua_settable(L, 2);
	lua_pop(L, 1);
	*/

	luaL_newmetatable(L, "ub_cb");
	lua_pop(L, 1);

	lua_createtable(L, 0, 1);
	luaL_register(L, NULL, lub_lib_funcs);
	return 1;
}

int luaopen_util_lunbound(lua_State* L) {
	return luaopen_lunbound(L);
}
