
.PHONY: all clean
.INTERMEDIATE: lunbound.o

LUA_VERSION = 5.2
LUA_DIR     = /usr/local
LUA_LIBDIR  = $(LUA_DIR)/lib/lua/$(LUA_VERSION)

CC          = ccache c99
CFLAGS     += -fPIC $(shell pkg-config --cflags lua-$(LUA_VERSION)) -Wall -Wextra -pedantic -ggdb
LDLIBS     += -lunbound
LDFLAGS    += -shared
WGET       ?= curl -sSfO

OUTPUT      = lunbound.so

default: lunbound.so

all: $(OUTPUT)

lunbound.o: lunbound.c iana_root_ta.h

iana_root_ta.h: root-anchors.xsl root-anchors.xml root-anchors.p7s icannbundle.pem
	openssl smime -verify -CAfile icannbundle.pem -inform der -in root-anchors.p7s -content root-anchors.xml
	xsltproc root-anchors.xsl root-anchors.xml > $@

root-anchors.xml root-anchors.p7s icannbundle.pem:
	$(WGET) https://data.iana.org/root-anchors/$@

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install:
	install -d $(DESTDIR)$(LUA_LIBDIR)/
	install -m644 lunbound.so $(DESTDIR)$(LUA_LIBDIR)/

clean:
	-rm -v $(OUTPUT)
