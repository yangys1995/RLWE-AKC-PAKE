CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -O3 -fomit-frame-pointer -msse2avx -march=corei7-avx -mavx2 -no-pie

HEADERS = crypto_stream_chacha20.h poly.h randombytes.h ntt.h crypto_hash_sha256.h  fips202.h crypto_stream_aes256ctr.h key_consensus.h pak.h params_pak.h
CFILES  = crypto_stream_chacha20.c poly.c precomp.c crypto_hash_sha256.c chacha.S cbd.s consts.c fips202.c omegas.c ntt_double.s pwmul.s bitrev.s crypto_stream_aes256ctr.o hr.s rec.s key_consensus.c pak.c


all:		test/speed  \
		test/new \


test/speed: $(HEADERS) $(CFILES) test/speed.c cpucycles.c randombytes.c
	$(CC) $(CFLAGS) $(CFILES) test/speed.c cpucycles.c randombytes.c -o $@

test/new:$(HEADERS) $(CFILES) test/new.c randombytes.c
	$(CC) $(CFLAGS) $(CFILES) test/new.c randombytes.c -o $@

crypto_stream_aes256ctr.o: crypto_stream_aes256ctr.c
	$(CC) -c -m64 -march=native -mtune=native -O3 -fomit-frame-pointer $^ -o $@

pwmul.q: ntt_double.py
	./ntt_double.py pwmul > $@

ntt_double.q: ntt_double.py
	./ntt_double.py > $@

.PHONY: clean

clean:
	-rm *.o	
	-rm test/speed
	-rm test/new

