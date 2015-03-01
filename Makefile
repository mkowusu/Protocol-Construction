#Authors : Michael Owusu & Camila Mateo
#Created : Fri Feb 28 22:10:22 CST 2015

CC = cc

CFLAGS = -g

all: main

main:  client.o server.o devurandom.o
	$(CC) -I/usr/include/nacl -o main client.o server.o devurandom.o main.c -lnacl

client.o: client.c
	$(CC) $(CFLAGS) -c -I/usr/include/nacl client.c 

server.o: server.c
	$(CC) $(CFLAGS) -c -I/usr/include/nacl server.c 

devurandom.o: devurandom.c 
	$(CC) $(CFLAGS) -c -I/usr/include/nacl devurandom.c 

clean:
	rm -f *.o *~ core*
