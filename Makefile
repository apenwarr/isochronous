CFLAGS+=-std=gnu99 -g
LDFLAGS+=-lrt -lm
PROGS=udpstress isoping isostream

all: $(PROGS)

udpstress: udpstress.c dscp.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

isoping: isoping.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

isostream: isostream.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(PROGS)
