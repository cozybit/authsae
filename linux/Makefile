#
CC=	gcc
CFLAGS=	-g -DLINUX -Wall -Werror  -I../../openssl-1.0.0-beta2/include -I..
LIBS= -L../../openssl-1.0.0-beta2
LDFLAGS=-lnl -lnl-genl -lcrypto -L/usr/local/lib -L.

all:	meshd meshd-nl80211 mon

meshd:	meshd.o ../common.o ../sae.o ../service.o ../ampe.o
	$(CC) -o meshd meshd.o ../common.o ../sae.o ../service.o ../ampe.o $(LIBS) -lcrypto

libsae.a: ../common.o ../sae.o ../service.o ../ampe.o
	ar rcs $@ $^

meshd-nl80211:	meshd-nl80211.o nlutils.o libsae.a
	$(CC) -o meshd-nl80211 meshd-nl80211.o nlutils.o -lsae $(LIBS) $(LDFLAGS)

mon:	mon.o ../service.o ../common.o
	$(CC) -o mon mon.o ../service.o ../common.o

clean:
	rm -f meshd *.o ../*.o *~ *.a
