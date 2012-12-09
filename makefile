PAM_LIB_DIR = $(DESTDIR)/lib/security
CC = gcc
LD = ld
INSTALL = /usr/bin/install
CFLAGS = -fPIC -O2 -c -g -Wall -Wformat-security -fno-strict-aliasing
LDFLAGS = --shared 
PAMLIB = -lpam -lcurl -lcrypto -lm
CPPFLAGS =

all: pam_totp.so

pam_totp.so: pam_totp.o hmac.o generator.o
	$(LD) $(LDFLAGS) -o pam_totp.so pam_totp.o hmac.o generator.o $(PAMLIB)

pam_totp.o: pam_totp.c
	$(CC) -fPIC $(CFLAGS) pam_totp.c $(PAMLIB)

hmac.o: hmac.h hmac.c
	$(CC) $(CFLAGS) -c hmac.c

generator.o: generator.c generator.h hmac.h
	$(CC) $(CFLAGS) -c generator.c

install: pam_totp.so
	$(INSTALL) -m 0755 -d $(PAM_LIB_DIR)
	$(INSTALL) -m 0644 pam_totp.so $(PAM_LIB_DIR)

clean:
	rm -f *.o pam_totp.so

spotless:
	rm -f pam_totp.so *.o *~ core

.PHONY: all clean spotless
