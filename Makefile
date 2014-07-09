
.PHONY: all clean
.INTERMEDIATE: lunbound.o

CFLAGS+=-fPIC
LDFLAGS+=-shared -lunbound

OUTPUT=use_unbound.lua lunbound.so
all: $(OUTPUT)

use_unbound.lua: fakedns.lua net.unbound.lua util.dns.lua util.lunbound.lua
	./squish.sh > $@

lunbound.o: lunbound.c iana_root_ta.h

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $^

clean:
	@rm -v $(OUTPUT)
