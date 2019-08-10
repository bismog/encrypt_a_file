# vmsec common service makefile
#default
default: all

# Compiler settings
CC      := g++

all:
	$(CC) -g -o xxx evp_encrypt.cpp base64.cpp -lcrypto

clean:
	rm -f xxx
    
.PHONY: clean all default

