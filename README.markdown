libunbound for Prosody
======================

This is a drop-in replacement for Prosodys internal DNS library with a binding to
libunbound.

Why use it
----------

This module can be used with [`mod_s2s_auth_dane`](http://code.google.com/p/prosody-modules/wiki/mod_s2s_auth_dane)
to support secure delegation and for [DANE](http://tools.ietf.org/html/rfc6698).

DNS commands in the prosody telnet console will also show DNSSEC status.

Downloading
-----------

Source can be downloaded with mercurial from <http://code.zash.se/luaunbound/>.

Building
--------

`./squish.sh > use_unbound.lua`

Installation
------------

1. Put `use_unbound.lua` in `/etc/prosody` or where your `prosody.cfg.lua` lives.
2. In the global section of your `prosody.cfg.lua`, add the following:

		RunScript "use_unbound.lua"
		resolvconf = "/etc/resolv.conf"
		hoststxt = "/etc/hosts"

3. Then start Prosody in LuaJIT. (How to do this is left as an exercise.)
4. If you have debug logging enabled, you should see logs from 'unbound' about
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

Links
-----

* <http://prosody.im/>
* <http://luajit.org/>
* <https://unbound.net/>

