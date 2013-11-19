# Makefile for RC4 cracker

CC = g++
CFLAGS = -Wall -c -Werror -std=c++11 -O2
LIBS = -lssl -lcrypto -lpthread 

ALL = rc4_cracker poledump

all: clean $(ALL)

rc4_cracker: rc4_cracker.o pole.o
	$(CC) -o $@ $^ $(LIBS)

rc4_cracker.o: rc4_cracker.cpp pole.h
	$(CC) $(CFLAGS) -c $< $(LIBS)

poledump: poledump.o pole.o
	$(CC) -o $@ $^

poledump.o: poledump.cpp pole.h
	$(CC) $(CFLAGS) -c $<

pole.o: pole.cpp pole.h
	$(CC) $(CFLAGS) -c $<

clean: 
	rm -f *.o $(ALL)
