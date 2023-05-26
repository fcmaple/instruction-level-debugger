

CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g
LDFLAGS =

ASM64	= yasm -f elf64 -DYASM -D__x86_64__

PROGS = sdb
all: $(PROGS)

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<
%.o: %.c
	$(CC) -c $(CFLAGS) $<

# sdb: sdb.o ptools.o util.o
# 	$(CXX) -o $@ $^ $(LDFLAGS) -lcapstone
sdb: main.o sdb.o ptools.o util.o
	$(CXX) -o $@ $^ $(LDFLAGS) -lcapstone
clean:
	rm -f *.o *~ $(PROGS)