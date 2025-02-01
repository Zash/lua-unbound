# luaunbound

This is a binding to [libunbound](https://unbound.net/) for
[Lua](https://www.lua.org/), allowing both asynchronous and
DNSSEC-secured DNS lookups of arbitrary DNS record types.

It was created because [Prosody](https://prosody.im/) needs an
asynchronous DNS library with support for SRV records, and the ones
found at the time did one or the other, or was missing DNSSEC that
allowed implementing
[DANE](https://www.internetsociety.org/resources/deploy360/dane/).

It originated out of a need in the [XMPP](https://xmpp.org/) server
software [Prosody](https://prosody.im/) for an async-capable resolver
library supporting SRV records, as well as a desire to experiment with
DNSSEC and new DNS records.

## Downloading

Source can be downloaded with Mercurial from
<https://code.zash.se/luaunbound/>.

Signed releases can be found at <https://code.zash.se/dl/luaunbound/>.

It is also available from [luarocks](https://luarocks.org/) and can be
installed by

    luarocks install luaunbound

## Building

    make

## API

### Creating a new context

The lunbound module has a single function, `new()` for creating a new
context. It takes a table with configuration as single optional
argument. If no argument is given the `config` table on the module will
be used.

### Config options

`async`
:   Uses threads if `true` or forks a process if `false`.

`hoststxt`
:   Path to `hosts.txt` file. If set to `true` then the default system
    `hosts.txt` file.

`resolvconf`
:   Path to resolver configuration. If set to `true` then the default
    system resolvers are used. Otherwise root hints are used.

`forward`
:   IP address of an upstream resolver(s) to use, a string or array of
    strings.

`trusted`
:   DNSSEC root trust anchors, a string or array of strings.

`trustfile`
:   Path to a file containing DNSSEC root trust anchors. Can be
    specified at compile-time (recommended for distributors).

`options`
:   Table allowing arbitrary settings from `unbound.conf`.

The built-in defaults are as follows:

``` lua
local resolver = require"luaunbound".new({
    async = true;
    hoststxt = true;
    resolvconf = true;
});
```

### Context methods

`ctx:resolve(name, type, class)`
:   Resolves name and returns a table with results.

`ctx:resolve_async(callback, name, type, class)`
:   Starts a query in async mode. Results are passed to the callback
    when the query is completed.

`ctx:fd()`
:   Returns a file descriptor that will appear readable when there are
    results available.

`ctx:process()`
:   Calls callbacks for all completed queries.

`ctx:wait()`
:   Blocks until all outstanding queries are completed and then calls
    callbacks for all completed queries.

`ctx:poll()`
:   Returns `true` if new results are available.

### Result table

The result table closely resembles libunbounds `struct ub_result`.

`qname`, `qtype` and `qclass`
:   Same as arguments to resolve methods.

`canonname`
:   The canonical name if the queried name was a CNAME. Note that full
    CNAME chasing is done by libunbound.

`rcode`, `havedata` and `nxdomain`
:   The DNS status code and flags indicating if any data is available.

`secure` and `bogus`

:   Indicates DNSSEC validation status. There are three possible
    combinations:

    -   Results are signed and validation succeeded, `secure` will be
        `true`.
    -   Results are signed but validation failed, `secure` will be
        `false` and `bogus` will be a string with an error message.
    -   The results were not signed. `secure` will be `false` and
        `bogus` will be `nil`.

The actual result data will be in the array part of the result table, in
the form of binary strings. It is your job to parse these into whatever
form you want.
