#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params_pak.h"

typedef struct {
  int32_t coeffs[PARAM_N];
} poly __attribute__ ((aligned (32)));

typedef struct {
  uint8_t coeffs[PARAM_N];
} poly_small;


void poly_uniform(poly *a, const unsigned char *seed);
void poly_getnoise(poly *r, unsigned char *seed, unsigned char nonce);
void poly_add(poly *r, const poly *a, const poly *b);

void poly_ntt(poly *r);
void poly_invntt(poly *r);
void poly_pointwise(poly *r, const poly *a, const poly *b);

void poly_frombytes(poly *r, const unsigned char *a);
void poly_tobytes(unsigned char *r, const poly *p);

void poly_small_frombytes(poly_small *r, const unsigned char *a);
void poly_small_tobytes(unsigned char *r, const poly_small *p);

#endif
