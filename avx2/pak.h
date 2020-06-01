#ifndef PAK_H
#define PAK_H

#include "poly.h"
#include "randombytes.h"
#include "crypto_stream_chacha20.h"
#include "error_correction.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

void pak_c0(unsigned char *send, poly *sk,unsigned char *state,const unsigned char *pw,const unsigned char *cid,const unsigned char *sid);
void pak_s0(unsigned char *send,const unsigned char *received, unsigned char *k_,const unsigned char *pw,const unsigned char *sid);
void pak_c1(unsigned char *sharedkey, unsigned char *send, const unsigned char *received,const poly *sk,unsigned char *state);
void pak_s1(unsigned char *sharedkey, const unsigned char *received,const unsigned char *k_);

#endif
