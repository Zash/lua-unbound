
.PHONY: all clean
.INTERMEDIATE: lunbound.o

CFLAGS+=-fPIC
LDLIBS+=-lunbound
LDFLAGS+=-shared
WGET?=curl -O

LUA_VERSION=5.1
LUA_DIR=/usr/local
LUA_LIBDIR=$(LUA_DIR)/lib/lua/$(LUA_VERSION)

OUTPUT=use_unbound.lua lunbound.so

default: lunbound.so
prosody: use_unbound.lua
all: $(OUTPUT)

paranoid:
	-rm iana_root_ta.h
	$(MAKE) all

use_unbound.lua: fakedns.lua net.unbound.lua util.dns.lua util.lunbound.lua
	./squish.sh > $@

lunbound.o: lunbound.c iana_root_ta.h

iana_root_ta.h:
	$(WGET) http://data.iana.org/root-anchors/root-anchors.xml
	$(WGET) http://data.iana.org/root-anchors/root-anchors.asc
	gpg --verify root-anchors.asc root-anchors.xml
	xsltproc root-anchors.xsl root-anchors.xml > $@

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install:
	install -m644 lunbound.so $(DESTDIR)$(LUA_LIBDIR)/

install-prosody: install
	install -m644 use_unbound.lua $(DESTDIR)/etc/prosody/

clean:
	@rm -v $(OUTPUT)
