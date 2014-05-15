
TARGET?=/usr/lib/prosody
INSTALL?=install -m644 --backup numbered

lunbound.so: lunbound.o
	$(LD) -o $@ $^ -shared -lunbound

.c.o:
		$(CC) -c -fPIC -o $@ $<

install-base:
	$(INSTALL) net.unbound.lua $(TARGET)/net/adns.lua
	$(INSTALL) fakedns.lua $(TARGET)/net/dns.lua
	$(INSTALL) util.dns.lua $(TARGET)/util/dns.lua
	$(INSTALL) util.dns.lua $(TARGET)/util/dns.lua

install-c: install-base
	$(INSTALL) lunbound.so $(TARGET)/util/lunbound.so

install-ffi: install-base
	$(INSTALL) util.lunbound.lua $(TARGET)/util/lunbound.lua

.PHONY: install-base install-c install-ffi
