
all: linux
	make -C $<

clean:
	rm -f *.o
	rm -f linux/*.o linux/meshd-nl80211 linux/meshd
	rm -f freebsd/*.o freebsd/meshd
