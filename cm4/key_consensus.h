#ifndef KEY_CONSENSUS_H
#define KEY_CONSENSUS_H

#include <stdlib.h>
#include <math.h>
#include "inttypes.h"
#include "params_pak.h"
#include "randombytes.h"
#include "crypto_stream_chacha20.h"
#include "poly.h"
#include <stdio.h>
#include <time.h>

void kccon(poly_small *v, const poly *sigma, unsigned char *key);//vxinhaozhi
void kcrec(unsigned char *key, const poly *sigma, const poly_small *v);

void akccon(poly_small *v, const poly *sigma, const unsigned char *key,const int *pre);//vxinhaozhi
void akcrec(unsigned char *key, const poly *sigma, const poly_small *v);


#endif
