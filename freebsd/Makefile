#
CC=     clang
#
CFLAGS=	-g -Wall -Werror -I/usr/local/include -I..
LIBS=   -L/usr/lib -L/usr/local/lib -L../build

all:	meshd mon

meshd:	meshd.o ../common.o ../sae.o ../service.o
	$(CC) -o meshd meshd.o ../common.o ../sae.o ../service.o $(LIBS) -lcrypto -lsae -lconfig

mon:	mon.o ../common.o ../service.o
	$(CC) -o mon mon.o ../common.o ../service.o $(LIBS) -lcrypto

clean:
	rm -f meshd mon *.o *~
