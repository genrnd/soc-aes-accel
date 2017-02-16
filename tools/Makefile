.PHONY: all

all: openssl_benchmark

openssl_benchmark: %: %.c
	$(CROSS_COMPILE)gcc -lcrypto -o $@ $^
