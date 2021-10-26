# https://github.com/croemheld/lkm-rootkit/blob/master/Makefile
# Module name
ROOTKIT := rootkit

# Build
BUILDDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

ifneq ($(KERNELRELEASE),)

# Module
obj-m := $(ROOTKIT).o

# Source
$(ROOTKIT)-y += src/core.o
$(ROOTKIT)-y += src/process_protection.o

else

all:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) clean

endif

