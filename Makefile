# Makefile for RC4 cracker

CC = g++
CFLAGS = -Wall -c -Werror -O2
LIBS = -lpthread 

ALL = rc4_cracker poledump

all: clean $(ALL)

rc4_cracker: rc4_cracker.o pole.o md5.o
	$(CC) -o $@ $^ $(LIBS)

rc4_cracker.o: rc4_cracker.cpp pole.h rc4_cracker.h md5.h
	$(CC) $(CFLAGS) -c $< $(LIBS)

poledump: poledump.o pole.o
	$(CC) -o $@ $^

poledump.o: poledump.cpp pole.h
	$(CC) $(CFLAGS) -c $<

pole.o: pole.cpp pole.h
	$(CC) $(CFLAGS) -c $<

md5.o: md5.cpp md5.h
	$(CC) $(CFLAGS) -c $<

clean: 
	rm -f *.o $(ALL)
