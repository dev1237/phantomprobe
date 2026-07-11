# phantomprobe -- portable C censorship-middlebox prober.
# Stages 1-2 use only normal sockets (no root, no libpcap).
# Stages 3-7 add raw sockets + libpcap + pthreads.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LDLIBS  ?= -lpcap -lpthread

OBJ = main.o net.o classify.o rawnet.o stages.o

phantomprobe: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

main.o:     phantomprobe.h rawnet.h stages.h
net.o:      phantomprobe.h
classify.o: phantomprobe.h
rawnet.o:   rawnet.h
stages.o:   phantomprobe.h rawnet.h stages.h

clean:
	rm -f *.o phantomprobe

.PHONY: clean
