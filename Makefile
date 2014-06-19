
all: use_unbound.lua lunbound.so

lunbound.so: lunbound.o
	$(LD) -o $@ $^ -shared -lunbound $(LDFLAGS)

use_unbound.lua: fakedns.lua net.unbound.lua util.dns.lua util.lunbound.lua
	./squish.sh > $@

.c.o:
	$(CC) -c -fPIC -o $@ $< $(CFLAGS)

clean:
	@rm -v lunbound.o lunbound.so use_unbound.lua

.PHONY: all
