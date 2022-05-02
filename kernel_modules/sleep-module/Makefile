obj-m += sleep.o
PWD   := $(CURDIR)

all: module usage

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

usage:
	gcc cat-nonblock.c -o cat_nonblock

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf cat_nonblock
