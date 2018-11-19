all:
	mkdir -p build; cd build; cmake ..; make

install:
	cd build; make install

clean:
	rm -rf build

test:
	cd tests && ./run_tests.sh
