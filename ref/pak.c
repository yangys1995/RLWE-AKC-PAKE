#include "poly.h"
#include "randombytes.h"
#include "key_consensus.h"
#include "fips202.h"
#include "pak.h"

static void encode_c0(unsigned char *r, const unsigned char *mbytes, const unsigned char *seed,const unsigned char *cid)
{
  int i;
  //poly_tobytes(r, m);
  for(i=0;i<POLY_BYTES;i++)
    r[i] = mbytes[i];
  for(i=0;i<ID_BYTES;i++)
  for(i=0;i<PAK_SEEDBYTES;i++)
    r[POLY_BYTES+i] = seed[i];
  for(i=0;i<ID_BYTES;i++)
    r[POLY_BYTES+PAK_SEEDBYTES+i]=cid[i];
}

static void decode_c0(poly *m, unsigned char *seed, unsigned char *cid,const unsigned char *r)
{
  int i;
  poly_frombytes(m, r);
  for(i=0;i<PAK_SEEDBYTES;i++)
    seed[i] = r[POLY_BYTES+i];
  for(i=0;i<ID_BYTES;i++)
    cid[i]=r[POLY_BYTES+PAK_SEEDBYTES+i];
}

static void encode_s0(unsigned char *r, const unsigned char *pk, const poly_small *v,const unsigned char *k)//c的每个系数2比特，一共N个系数
{
  int i;
  poly_small_tobytes(r,v);
  for(i=0;i<POLY_BYTES;i++)
    r[POLY_SMALL_BYTES+i] = pk[i];
  for(i=0;i<PAK_VERBYTES;i++)
    r[POLY_BYTES+POLY_SMALL_BYTES+i]=k[i];
}

static void decode_s0(unsigned char *pkbbytes,poly *pkb, poly_small *v,unsigned char *k, const unsigned char *r)
{
  int i;
  poly_small_frombytes(v, r);
  for(i=0;i<POLY_BYTES;i++)
    pkbbytes[i] = r[POLY_SMALL_BYTES+i];
  poly_frombytes(pkb,pkbbytes);
  for(i=0;i<PAK_VERBYTES;i++)
    k[i]=r[POLY_BYTES+POLY_SMALL_BYTES+i];
}

static void gen_a(poly *a, const unsigned char *seed)
{
    poly_uniform(a,seed);
}


// API FUNCTIONS 
void pak_c0(unsigned char *send, poly *sk,unsigned char *state,const unsigned char *pw,const unsigned char *cid,const unsigned char *sid){
  poly a, e, r, pk, gamma, m;
  unsigned char seed[PAK_SEEDBYTES];
  unsigned char noiseseed[32];

  randombytes(seed, PAK_SEEDBYTES);
  randombytes(noiseseed, 32);

  gen_a(&a, seed);

  poly_getnoise(sk,noiseseed,0);
  poly_ntt(sk);
  
  poly_getnoise(&e,noiseseed,1);
  poly_ntt(&e);

  poly_pointwise(&r,sk,&a);
  poly_add(&pk,&e,&r);

  poly_uniform(&gamma,pw);
  poly_add(&m,&pk,&gamma);

  int i;
  for(i=0;i<ID_BYTES;i++){
    state[i]=cid[i];
    state[i+ID_BYTES]=sid[i];
  }
  unsigned char mbytes[POLY_BYTES];
  poly_tobytes(mbytes,&m);
  for(i=0;i<POLY_BYTES;i++){
    state[i+2*ID_BYTES]=mbytes[i];
  }
  unsigned char gammabytes[POLY_BYTES];
  for(i=0;i<PARAM_N;i++){
    gamma.coeffs[i]=PARAM_Q-gamma.coeffs[i];
  }
  poly_tobytes(gammabytes,&gamma);
  for(i=0;i<POLY_BYTES;i++){
    state[i+2*ID_BYTES+2*POLY_BYTES+PAK_KEYBYTES]=gammabytes[i];
  }

  encode_c0(send, mbytes, seed,cid);
}

void pak_s0(unsigned char *send,const unsigned char *received, unsigned char *k_,const unsigned char *pw,const unsigned char *sid){
  poly s, e, sigma, a, pka, pk,m,gamma;
  poly_small v;
  unsigned char seed[PAK_SEEDBYTES];
  unsigned char noiseseed[32];
  unsigned char cid[ID_BYTES];
  unsigned char key[PAK_KEYBYTES];
  unsigned char state[HASH_BYTES];

  randombytes(noiseseed, 32);

  decode_c0(&m, seed,cid, received);
  
  poly_uniform(&gamma,pw);
  int i;
  for(i=0;i<PARAM_N;i++){
    gamma.coeffs[i]=PARAM_Q-gamma.coeffs[i];
  }
  poly_add(&pka,&m,&gamma);

  gen_a(&a, seed);

  poly_getnoise(&s,noiseseed,0);
  poly_ntt(&s);
  poly_getnoise(&e,noiseseed,1);
  poly_ntt(&e);

  poly_pointwise(&pk, &a, &s);
  poly_add(&pk, &pk, &e);
  
  poly_pointwise(&sigma, &pka, &s);
  poly_invntt(&sigma);

  kccon(&v, &sigma, key);

  for(i=0;i<ID_BYTES;i++){
    state[i]=cid[i];
    state[i+ID_BYTES]=sid[i];
  }
  unsigned char mbytes[POLY_BYTES];
  poly_tobytes(mbytes,&m);
  for(i=0;i<POLY_BYTES;i++){
    state[i+2*ID_BYTES]=mbytes[i];
  }
  unsigned char pkbytes[POLY_BYTES];
  poly_tobytes(pkbytes,&pk);
  for(i=0;i<POLY_BYTES;i++){
    state[i+2*ID_BYTES+POLY_BYTES]=pkbytes[i];
  }
  for(i=0;i<PAK_KEYBYTES;i++){
    state[i+2*ID_BYTES+2*POLY_BYTES]=key[i];
  }
  unsigned char gammabytes[POLY_BYTES];
  poly_tobytes(gammabytes,&gamma);
  for(i=0;i<POLY_BYTES;i++){
    state[i+2*ID_BYTES+2*POLY_BYTES+PAK_KEYBYTES]=gammabytes[i];
  }
  
  unsigned char k[PAK_VERBYTES];

#ifndef STATISTICAL_TEST 
  sha3256(k, state, HASH_BYTES);
  sha3256(k_,k,PAK_VERBYTES);
#endif
  encode_s0(send,pkbytes,&v,k);
  
}

void pak_c1(unsigned char *sharedkey, unsigned char *send, const unsigned char *received,const poly *sk,unsigned char *state){
  poly pkb,sigma;
  poly_small v;
  unsigned char key[PAK_KEYBYTES];
  unsigned char kb[PAK_VERBYTES];
  unsigned char pkbbytes[POLY_BYTES];

  decode_s0(pkbbytes,&pkb, &v,kb, received);

  poly_pointwise(&sigma,sk,&pkb);
  poly_invntt(&sigma);

  kcrec(key,&sigma,&v);

  int i;
  for(i=0;i<POLY_BYTES;i++){
    state[i+2*ID_BYTES+POLY_BYTES]=pkbbytes[i];
  }
  for(i=0;i<PAK_KEYBYTES;i++){
    state[i+2*ID_BYTES+2*POLY_BYTES]=key[i];
  }
  
  unsigned char k[PAK_VERBYTES];
  //unsigned char k_[PAK_VERBYTES];

#ifndef STATISTICAL_TEST 
  sha3256(k, state, HASH_BYTES); 
  //sha3256(k_, k, PAK_VERBYTES);
  
#endif
  //send=k_;
  //sha3256(sharedkey,k_,PAK_VERBYTES);
  if(memcmp(kb,k,32)==0){
    sha3256(send, k, PAK_VERBYTES);
    sha3256(sharedkey,send,PAK_VERBYTES);
  }
  
}

void pak_s1(unsigned char *sharedkey, const unsigned char *received,const unsigned char *k_){
  if(memcmp(received,k_,32)==0)
    sha3256(sharedkey,k_,PAK_VERBYTES);
}


