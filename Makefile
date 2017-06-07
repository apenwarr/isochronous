CFLAGS+=-std=gnu99 -g
CXXFLAGS+=-std=c++11 -g

UNAME := $(shell uname -s)
ifneq ($(UNAME),Darwin)
LDFLAGS+=-lrt -lm
endif

PROGS=udpstress isoping isostream

all: $(PROGS)

udpstress: udpstress.c dscp.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

isoping: isoping.cc isoping_main.cc
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

isostream: isostream.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(PROGS) *~ .*~ *.o
	rm -rf *.dSYM
