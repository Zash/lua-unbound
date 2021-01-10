
.PHONY: all clean
.INTERMEDIATE: lunbound.o

LUA_VERSION = 5.2
LUA_LIBDIR  = $(shell pkg-config --variable=INSTALL_CMOD lua-$(LUA_VERSION))

CC          = c99
CFLAGS     += -fPIC $(shell pkg-config --cflags lua-$(LUA_VERSION)) -Wall -Wextra -pedantic -ggdb
LDLIBS     += -lunbound
LDFLAGS    += -shared

CFLAGS     += $(MYCFLAGS)
LDFLAGS    += $(MYLDFLAGS)

OUTPUT      = lunbound.so

MKDIR       = install -d
INSTALL     = install -m644

default: lunbound.so

all: $(OUTPUT)

lunbound.o: lunbound.c

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install:
	$(MKDIR) $(DESTDIR)$(LUA_LIBDIR)/
	$(INSTALL) lunbound.so $(DESTDIR)$(LUA_LIBDIR)/

clean:
	-rm -v $(OUTPUT)
