
all: linux
	make -C $<

clean:
	rm -f *.o
	rm -f linux/*.o
	rm -f freebsd/*.o
