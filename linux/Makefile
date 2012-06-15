
CFLAGS += -g -DLINUX -Wall -I..
LDFLAGS += -L.
PREFIX ?= /usr/

ifndef IS_OPENWRT
	CFLAGS += -Werror
	NLLIBS = -lnl-3 -lnl-genl-3
else
	NLLIBS = -lnl -lnl-genl
endif

all:	meshd meshd-nl80211 mon

meshd:	meshd.o ../common.o ../sae.o ../service.o ../ampe.o ../crypto/aes_siv.o
	$(CC) -o $@ $^ $(LDFLAGS) -lcrypto -lconfig

libsae.a: ../common.o ../sae.o ../service.o ../ampe.o ../crypto/aes_siv.o
	ar rcs $@ $^

meshd-nl80211:	meshd-nl80211.o nlutils.o libsae.a
	$(CC) -o $@ $^ $(LDFLAGS) -lsae $(NLLIBS) -lcrypto  -lconfig

mon:	mon.o ../service.o ../common.o
	$(CC) $^ -o $@

install: meshd meshd-nl80211 mon
	cp $^ $(PREFIX)/bin/

clean:
	rm -f meshd *.o ../*.o *~ *.a
