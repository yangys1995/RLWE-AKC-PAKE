#include "../pak.h"
#include "../poly.h"
#include "../stm32f4_wrapper.h"
#include <stdlib.h>
#include <stdio.h>

#define NTESTS 2


static void print_results(const char *s, unsigned int *t, size_t tlen)
{
  unsigned char output[32];
  sprintf((char *)output,"%s", s);
  send_USART_str(output);
  sprintf((char *)output,"median: %u",t[1]-t[0]);
  send_USART_str(output);
}

#define cpucycles() (*DWT_CYCCNT);

unsigned int t[NTESTS];

int main()
{
  clock_setup();
  gpio_setup();
  usart_setup(115200);
  rng_setup();
  volatile unsigned int *DWT_CYCCNT = (unsigned int *)0xE0001004;
  volatile unsigned int *DWT_CTRL = (unsigned int *)0xE0001000;
  volatile unsigned int *SCB_DEMCR = (unsigned int *)0xE000EDFC;

  *SCB_DEMCR = *SCB_DEMCR | 0x01000000;
  *DWT_CYCCNT = 0; // reset the counter
  *DWT_CTRL = *DWT_CTRL | 1 ; // enable the counter
  uint32_t urnd[1024];
  unsigned char output[32];
  
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
  
  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    randombytes(seed, 32);
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
    poly_bitrev(&sk_a);
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
    poly_getnoise_fast(&sk_a,seed,0);
  }
  print_results("poly_getnoise_fast: ", t, NTESTS);

 for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    random_int(urnd,1024);
  }
  print_results("random: ", t, NTESTS);
  
  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    helprec(&sk_a, &sk_a, seed, 0);
  }
  print_results("helprec: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    rec(key_a, &sk_a, &sk_a);
  }
  print_results("rec: ", t, NTESTS);

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
    
  sprintf((char *)output, "done");
  send_USART_str(output);
  signal_host();
 
  return 0;
}
