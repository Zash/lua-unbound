libunbound for Prosody
======================

This is a drop-in replacement for Prosodys internal DNS library with a
binding to libunbound.

Why use it
----------

This module can be used with [`mod_s2s_auth_dane`][daneplugin] to support secure
delegation and for [DANE][].

DNS commands in the prosody telnet console will also show DNSSEC status.

Downloading
-----------

Source can be downloaded with mercurial from <http://code.zash.se/luaunbound/>.

Dependencies
------------

* Required
  * libunbound
* Optional
  * LuaJIT 2
* Build-time (not required with LuaJIT)
  * Lua headers
  * libunbound headers

Building
--------

`./squish.sh > use_unbound.lua`

To build the C module (can be skipped if running under LuaJIT):

  make

Installation
------------

1. Put `use_unbound.lua` in `/etc/prosody` or where your `prosody.cfg.lua` lives.

2. Install the C module (can be skipped if running under LuaJIT):

    sudo install lunbound.so /path/to/prosody/util/

3. In the global section of your `prosody.cfg.lua`, add the following:

		RunScript "use_unbound.lua"
		resolvconf = "/etc/resolv.conf"
		hoststxt = "/etc/hosts"

4. Then start Prosody.  (Running under LuaJIT is left as an exercise.)
5. If you have debug logging enabled, you should see logs from 'unbound' about
  lookups performed.

Configuration
-------------

* `resolvconf` - string, filename

  Optional, but recommended. Point to a file with a list of name
  servers to use, such as `/etc/resolv.conf`.  If left out,
  unbound will perform a full lookup from scratch from the DNS
  roots.

* `hoststxt` - string, filename

  Optional. Point to a file like /etc/hosts or similar. Note that
  XMPP servers use SRV lookups first to know where to connect to.

Modules
-------

* `net.unbound`

  API-compatible with prosodys `net.adns` DNS library.

* `util.lunbound`

  The module that wraps libunbound.

* `util.dns`

  DNS parsing library.

util.lunbound API
-----------------

### Creating a new context

The lunbound module has a single function, `new()` for creating a new
context.  It takes a table with configuration as single optional
argument.  If no argument is given the `config` table on the module will
be used.

### Config options

* `async`: Uses threads if `true` or forks a process if `false`.
* `hoststxt`: Path to `hosts.txt` file.  If set to `true` then the
  default system `hosts.txt` file.
* `resolvconf`: Path to resolver configuration.  If set to `true` then
  the default system resolvers are used.  Otherwise root hints are used.
* `trusted`: DNSSEC root trust anchors, a string or array of strings.
  Defaults to hard-coded IANA root anchors.

### Context methods

* `ctx:resolve(name, type, class)`

  Resolves name and returns a table with results.

* `ctx:resolve_async(callback, name, type, class)`

  Starts a query in async mode.  Results are passed to the
  callback when the query is completed.

* `ctx:fd()`

  Returns a file descriptor that will appear readable when there
  are results available.

* `ctx:process()`

  Calls callbacks for all completed queries.

* `ctx:wait()`

  Blocks until all outstanding queries are completed and then
  calls callbacks for all completed queries.

* `ctx:poll()`

  Returns `true` if new results are available.

### Result table

The result table closely resembles libunbounds result struct.

* `qname`, `qtype` and `qclass`

  Same as arguments to resolve methods.

* `canonname`

  The canonical name if the queried name was a CNAME.  Note that
  full CNAME chasing is done by libunbound.

* `rcode`, `havedata` and `nxdomain`

  The DNS status code and flags indicating if any data is available.

* `secure` and `bogus`

  Indicates DNSSEC validation status.  There are three possible combinations:

  * Results are signed and validation succeeded, `secure`
    will be `true`.
  * Results are signed but validation failed, `secure` will
    be `false` and `bogus` will be a string with an error
    message.
  * The results were not signed.  `secure` will be `false`
    and `bogus` will be `nil`.

* The actual result data will be in the array part of the result table,
  in the form of binary strings.  Use `util.dns` to parse them into
  something usable.

util.dns API
------------

The most interesting part of `util.dns` is probably the RR parsers,
available in the `parsers` table on the module.  For example, to parse
an A record, `dns.parsers.A(data)` returns a formatted IPv4 address.
Parsers return either a string for simple types or a table for more
complicated types, such as SOA, MX or SRV.

* The `classes`, `types`, `errors` and `params` tables map
  various DNS parameters to string names.
* `classes` and `types` map integer types to names and vice
  versa.
* `errors` maps the `rcode` integer to an abbreviated error
  name, and that name to a friendlier message.
* Finally, `params` contain symbolic names for some record
  types.

Links
-----

* <http://prosody.im/>
* <http://luajit.org/>
* <https://unbound.net/>

[daneplugin]: http://code.google.com/p/prosody-modules/wiki/mod_s2s_auth_dane
[DANE]: http://tools.ietf.org/html/rfc6698
