#include "../pak.h"
#include "../poly.h"
#include "../key_consensus.h"
#include "../cpucycles.h"
#include <stdlib.h>
#include <stdio.h>

#define NTESTS 1000

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
  unsigned long long acc=0;
  size_t i;
  for(i=0;i<tlen;i++)
    acc += t[i];
  return acc/(tlen);
}

static void print_results(const char *s, unsigned long long *t, size_t tlen)
{
  size_t i;
  printf("%s", s);
  for(i=0;i<tlen-1;i++)
  {
    t[i] = t[i+1] - t[i];
  //  printf("%llu ", t[i]);
  }
  printf("\n");
  printf("median: %llu\n", median(t, tlen));
  printf("average: %llu\n", average(t, tlen-1));
  printf("\n");
}


unsigned long long t[NTESTS];

int main()
{
  poly sk_a;
  poly_small v;
  //unsigned char key_a[32], key_b[32];
  unsigned char sendc0[PAK_SENDC0BYTES];
  unsigned char sends0[PAK_SENDS0BYTES];
  unsigned char sendc1[PAK_SENDC1BYTES];
  unsigned char statec[HASH_BYTES];
  //unsigned char states[HASH_BYTES];
  unsigned char pw[PW_BYTES]="65478543";
  unsigned char sid[ID_BYTES]="12345678";
  unsigned char cid[ID_BYTES]="23456789";
  unsigned char kc[32];
  unsigned char ks[32];
  unsigned char keys[128];
  //unsigned char keyc[128];
  unsigned char k_[PAK_VERBYTES];
  unsigned char seed[PAK_SEEDBYTES];
  poly sk;
  int i;

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    randombytes(seed, PAK_SEEDBYTES);
    poly_uniform(&sk_a, seed);
  }
  print_results("poly_uniform: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    poly_ntt(&sk_a);
  }
  print_results("poly_ntt: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    poly_invntt(&sk_a);
  }
  print_results("poly_invntt: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    poly_getnoise(&sk_a,seed,0);
  }
  print_results("poly_getnoise: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    kccon(&v, &sk_a, keys);
  }
  print_results("kccon: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    kcrec(keys, &sk_a, &v);
  }
  print_results("kcrec: ", t, NTESTS);

  uint8_t tmp=0;
  int pre[PARAM_N];
  for(i=0;i<PARAM_N;i++){
    if((i&0x7)==0)
        tmp=keys[i>>3];
    if((tmp>>7)==1)
        pre[i]=393280;
    else
        pre[i]=0;
    tmp=(tmp<<1);
    }

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    akccon(&v, &sk_a, keys,pre);
  }
  print_results("akccon: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    akcrec(keys, &sk_a, &v);
  }
  print_results("akcrec: ", t, NTESTS);
  
  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    pak_c0(sendc0,&sk,statec,pw,cid,sid);
  }
  print_results("pak_c0: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    pak_s0(sends0,sendc0,k_,pw,sid);
  }
  print_results("pak_s0: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    pak_c1(kc,sendc1,sends0,&sk,statec);
  }
  print_results("pak_c1: ", t, NTESTS);
    
  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    pak_s1(ks,sendc1,k_);
  }
  print_results("pak_s1: ", t, NTESTS);
  
  return 0;
}
