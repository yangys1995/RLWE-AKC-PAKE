
#include "../stm32f4_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../params_pak.h"
#include "../poly.h"
#include "../pak.h"



#define MAXSTACK 50000
unsigned char sendc0[PAK_SENDC0BYTES];
unsigned char sends0[PAK_SENDS0BYTES];
unsigned char sendc1[PAK_SENDC1BYTES];
unsigned char statec[HASH_BYTES];
unsigned char pw[PW_BYTES]="65478543";
  unsigned char sid[ID_BYTES]="12345678";
  unsigned char cid[ID_BYTES]="23456789";
  unsigned char kc[32];
  unsigned char ks[32];
  unsigned char keys[128];
  //unsigned char keyc[128];
  unsigned char k_[PAK_VERBYTES];
  unsigned char seed[PAK_SEEDBYTES];
	

unsigned char output[32];
unsigned int ctr;
unsigned char canary;
volatile unsigned char *p;
extern unsigned char _end; 

static unsigned int stack_count(unsigned char canary,volatile unsigned char *a)
{
  volatile unsigned char *p = (a-MAXSTACK);
  unsigned int c = 0;
  while(*p == canary && p < a)
  {
    p++;
    c++;
  }
  return c;
} 

#define WRITE_CANARY(X) {p=X;while(p>= (X-MAXSTACK)) *(p--) = canary;}
 
int main(void)
{
    clock_setup();
    gpio_setup();
    usart_setup(115200);
    rng_setup();


	volatile unsigned char a; /* Mark the beginning of the stack */
	int i;
	poly sk;
    canary = 42;

    WRITE_CANARY(&a);
	pak_c0(sendc0,&sk,statec,pw,cid,sid);
    ctr = MAXSTACK - stack_count(canary,&a);
	sprintf((char *)output, "RAM usage of c0: %d",ctr);
    send_USART_str(output);
	
	WRITE_CANARY(&a);
	pak_s0(sends0,sendc0,k_,pw,sid);
    ctr = MAXSTACK - stack_count(canary,&a);
	sprintf((char *)output, "RAM usage of s0: %d",ctr);
    send_USART_str(output);
	   


	WRITE_CANARY(&a);   
	pak_c1(kc,sendc1,sends0,&sk,statec);
    ctr = MAXSTACK - stack_count(canary,&a);
	sprintf((char *)output, "RAM usage of c1: %d",ctr);
    send_USART_str(output);
	
	WRITE_CANARY(&a);   
	pak_s1(ks,sendc1,k_);
    ctr = MAXSTACK - stack_count(canary,&a);
	sprintf((char *)output, "RAM usage of s1: %d",ctr);
    send_USART_str(output);
	      
	WRITE_CANARY(&a);
	pak_c0(sendc0,&sk,statec,pw,cid,sid);
 	pak_s0(sends0,sendc0,k_,pw,sid);
    pak_c1(kc,sendc1,sends0,&sk,statec);
	pak_s1(ks,sendc1,k_);
    ctr = MAXSTACK - stack_count(canary,&a);
	sprintf((char *)output, "RAM usage of KEM: %d",ctr);
    send_USART_str(output);
	
    sprintf((char *)output, "done!");
    send_USART_str(output);
    signal_host();

}
