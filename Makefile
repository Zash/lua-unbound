
.PHONY: all clean
.INTERMEDIATE: lunbound.o

CFLAGS+=-fPIC
LDLIBS+=-lunbound
LDFLAGS+=-shared
WGET?=curl -O

OUTPUT=use_unbound.lua lunbound.so
all: $(OUTPUT)

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

clean:
	@rm -v $(OUTPUT)
