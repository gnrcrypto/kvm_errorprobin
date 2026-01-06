# KVM Probe Driver and Tools Makefile
# 
# USAGE:
# 1. Build: make
# 2. Load: sudo insmod kvm_probe_drv.ko
# 3. Use: ./kvm_prober help
# 4. Exploit: ./ahci_exploit --help
#
# The driver runs hypercalls 100-103 after every read/write/scan
# and reports interesting results to dmesg.

obj-m := kvm_probe_drv.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: driver tools

driver:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

tools: kvm_prober kvm_pwn exploit

kvm_prober: kvm_prober.c
	gcc -o kvm_prober kvm_prober.c -Wall -O2
	cp kvm_prober /bin

kvm_pwn: kvm_pwn.c
	gcc -o kvm_pwn kvm_pwn.c -Wall -O2
	cp kvm_pwn /bin

exploit: exploit.c
	gcc -o exploit exploit.c -Wall -O2
	cp exploit /bin

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f kvm_prober kvm_pwn exploit
	rm /bin/kvm_prober
	rm /bin/kvm_pwn
  rm /bin/exploit

install: driver
	sudo rmmod kvm_probe_drv 2>/dev/null || true
	sudo insmod kvm_probe_drv.ko
	@echo "Module loaded. Device: /dev/kvm_probe_dev"
	sudo cp kvm_prober /bin
	sudo cp kvm_pwn /bin
  sudo cp exploit /bin

unload:
	sudo rmmod kvm_probe_drv

# Watch dmesg for CTF results in real-time
watch-ctf:
	sudo dmesg -w | grep --line-buffered -E "CTF|Hypercall"

.PHONY: all driver tools clean install unload watch-ctf
