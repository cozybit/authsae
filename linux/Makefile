#
CC=	gcc
CFLAGS=	-g -DLINUX -Wall -Werror  -I../../openssl-1.0.0-beta2/include -I.. 
LIBS= -L../../openssl-1.0.0-beta2

all:	meshd mon

meshd:	meshd.o ../common.o ../sae.o ../service.o
	$(CC) -o meshd meshd.o ../common.o ../sae.o ../service.o $(LIBS) -lcrypto

mon:	mon.o ../service.o ../common.o
	$(CC) -o mon mon.o ../service.o ../common.o

clean:
	rm -f meshd *.o ../*.o *~
