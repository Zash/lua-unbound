local record lunbound

	record ub_config
		async : boolean
		resolvconf : string | boolean
		hoststxt : string | boolean
		forward : { string } | string
		trusted : { string } | string
		trustfile : string
		options : { string : string }
	end

	enum ub_state
		"pending"
		"ready"
		"done"
		"unknown"
	end

	record ub_result
		qname : string
		qtype : integer
		qclass : integer
		havedata : boolean
		canonname : string
		nxdomain : boolean
		secure : boolean
		bogus : string
		rcode : integer
		{ string }
		n : integer
	end

	record ub_query
	end

	record ub_ctx
		getfd : function (ub_ctx) : integer
		resolve : function (ub_ctx, string, integer, integer) : ub_result, string
		resolve_async : function (ub_ctx, function(ub_result, string), string, integer, integer) : ub_query, string
		cancel : function (ub_ctx, ub_query) : boolean, string
		process : function (ub_ctx) : integer
		wait : function (ub_ctx) : integer
		poll : function (ub_ctx) : boolean
	end

	new : function (ub_config) : ub_ctx
	_VERSION : string
	_LIBVER : string
	config : ub_config

end
return lunbound
