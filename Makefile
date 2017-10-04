ifneq ($(KERNELRELEASE),)
	ccflags-y := -DDEBUG=1
	obj-m := secret.o

else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif
