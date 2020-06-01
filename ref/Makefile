CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -O3 -fomit-frame-pointer -msse2avx -march=corei7-avx

HEADERS = crypto_stream_chacha20.h poly.h randombytes.h ntt.h reduce.h key_consensus.h pak.h params_pak.h
CFILES  = crypto_stream_chacha20.c poly.c ntt.c precomp.c reduce.c fips202.c key_consensus.c pak.c

all:	test/speed  \
	test/new \


test/speed: $(HEADERS) $(CFILES) test/speed.c cpucycles.c randombytes.c
	$(CC) $(CFLAGS) $(CFILES) randombytes.c test/speed.c cpucycles.c -lm -o $@

test/new:$(HEADERS) $(CFILES) test/new.c randombytes.c
	$(CC) $(CFLAGS) $(CFILES) test/new.c randombytes.c -lm -o $@
.PHONY: clean

clean:
	-rm test/speed
	-rm test/new

