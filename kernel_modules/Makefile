KERNEL_SOURCE := /lib/modules/$(shell uname -r)/build
PWD           := $(shell pwd)
obj-m         += epoll_reactor_module.o

all:
	make -C $(KERNEL_SOURCE) M=$(PWD) modules

clean:
	make -C $(KERNEL_SOURCE) M=$(PWD) clean

install:
	sudo rmmod epoll_reactor_module.ko
	sudo insmod epoll_reactor_module.ko
