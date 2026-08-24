obj-m += sec_mem.o
path=../chall_vm/build/linux-6.12.9/
ccflags-y += -march=armv8.5-a -mbranch-protection=standard

all:
	make -C $(path) M=$(PWD) modules
