
CFLAGS+=-fPIC
LDFLAGS+=-shared -lunbound

OUTPUT=use_unbound.lua lunbound.so
all: $(OUTPUT)

use_unbound.lua: fakedns.lua net.unbound.lua util.dns.lua util.lunbound.lua
	./squish.sh > $@

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $^

clean:
	@rm -v $(OUTPUT)

.PHONY: all
