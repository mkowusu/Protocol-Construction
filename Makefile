#Authors : Michael Owusu & Camila Mateo
#Created : Fri Feb 28 22:10:22 CST 2015

CC = cc

# Set compilation flags
#   -ansi (check syntax against the American National Standard for C
CFLAGS = -Wall -g

all: main

main: main.o client.o server.o 
	$(CC) -I/usr/include/nacl -lnacl -o main main.o client.o server.o

main.o: main.c crypto_box.h
	$(CC) $(CFLAGS) -c main.c 

client.o: client.c crypto_box.h
	$(CC) $(CFLAGS) -c client.c 

server.o: server.c crypto_box.h
	$(CC) $(CFLAGS) -c server.c 

clean:
	rm -f *.o *~ core*
