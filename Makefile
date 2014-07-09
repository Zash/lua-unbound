
.PHONY: all clean
.INTERMEDIATE: lunbound.o

CFLAGS+=-fPIC
LDFLAGS+=-shared -lunbound
WGET?=curl -O

OUTPUT=use_unbound.lua lunbound.so
all: $(OUTPUT)

use_unbound.lua: fakedns.lua net.unbound.lua util.dns.lua util.lunbound.lua
	./squish.sh > $@

lunbound.o: lunbound.c iana_root_ta.h

iana_root_ta.h: root-anchors.xml root-anchors.asc
	gpg --verify root-anchors.asc root-anchors.xml
	xsltproc root-anchors.xsl root-anchors.xml > $@

root-anchors.xml:
	$(WGET) http://data.iana.org/root-anchors/root-anchors.xml

root-anchors.asc:
	$(WGET) http://data.iana.org/root-anchors/root-anchors.asc

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $^

clean:
	@rm -v $(OUTPUT)
