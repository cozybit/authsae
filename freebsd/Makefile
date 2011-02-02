#
CC=	gcc
#
CFLAGS=	-g -Wall -Werror  -I../../openssl-1.0.0-beta2/include -I.. 
LIBS= -L../../openssl-1.0.0-beta2

all:	meshd mon

meshd:	meshd.o ../common.o ../sae.o ../service.o
	$(CC) -o meshd meshd.o common.o sae.o service.o $(LIBS) -lcrypto

mon:	mon.o ../common.o ../service.o
	$(CC) -o mon mon.o common.o service.o $(LIBS) -lcrypto

clean:
	rm -f meshd mon *.o *~
