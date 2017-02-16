ifndef KERNELRELEASE # We have been called by the user

ifndef KDIR
  $(error "KDIR must be set to build modules")
endif

ARCH=arm
CROSS_COMPILE?=arm-linux-gnueabihf-
export CROSS_COMPILE ARCH

modules: $(wildcard *.c)
	make -C $(KDIR) W=1 M=$(shell pwd) modules

tools:
	make -C $(shell pwd)/tools

clean disclean:
	make -C $(KDIR) M=$(shell pwd) $@

.PHONY: tools

else # We have been called by the Kbuild

subdir-ccflags-y := -Wno-sign-compare
obj-m += aes-crypto-api-iface.o

endif # KERNELRELEASE
