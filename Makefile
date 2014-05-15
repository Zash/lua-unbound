
lunbound.so: lunbound.o
	$(LD) -o $@ $^ -shared -lunbound

.c.o:
		$(CC) -c -fPIC -o $@ $<


