
.PHONY: all clean
.INTERMEDIATE: lunbound.o

LUA_VERSION = 5.2
LUA_DIR     = /usr/local
LUA_LIBDIR  = $(LUA_DIR)/lib/lua/$(LUA_VERSION)

CC          = c99
CFLAGS     += -fPIC $(shell pkg-config --cflags lua-$(LUA_VERSION)) -Wall -Wextra -pedantic -ggdb
LDLIBS     += -lunbound
LDFLAGS    += -shared

OUTPUT      = lunbound.so

default: lunbound.so

all: $(OUTPUT)

lunbound.o: lunbound.c

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install:
	install -d $(DESTDIR)$(LUA_LIBDIR)/
	install -m644 lunbound.so $(DESTDIR)$(LUA_LIBDIR)/

clean:
	-rm -v $(OUTPUT)
