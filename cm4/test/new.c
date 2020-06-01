#include<stdio.h>
#include <stdlib.h>
#include "../randombytes.h"
#include "../poly.h"
#include "../fips202.h"
#include "../crypto_stream_chacha20.h"
#include "../ntt.h"
#include "../reduce.h"
#include "../key_consensus.h"
#include "../pak.h"



int tmp()
{
	poly r1;
  poly r2;
	unsigned char pw[8]="abcdefgh";
	int i;

  poly_uniform(&r1,pw);
  poly_uniform(&r2,pw);
  for(i=0;i<1024;i++){
    r2.coeffs[i]=12289-r2.coeffs[i];
  }
  poly a, e, r, pk,sk;
  unsigned char seed[PAK_SEEDBYTES];
  unsigned char noiseseed[32];

  randombytes(seed, PAK_SEEDBYTES);
  randombytes(noiseseed, 32);

  poly_uniform(&a, seed);

  poly_getnoise(&sk,noiseseed,0);
  poly_ntt(&sk);
  
  poly_getnoise(&e,noiseseed,1);
  poly_ntt(&e);

  poly_pointwise(&r,&sk,&a);
  poly_add(&pk,&e,&r);

  //poly_ntt(&r1);
  poly tmp1;
  poly_add(&tmp1,&pk,&r1);
  /*
  for(i=0;i<1024;i++){
    tmp1.coeffs[i]=pk.coeffs[i]+r1.coeffs[i];
    while(tmp1.coeffs[i]>=12289)
      tmp1.coeffs[i]-=12289;
  }
  poly tmp2;
  for(i=0;i<1024;i++){
    tmp2.coeffs[i]=tmp1.coeffs[i]+r2.coeffs[i];
    while(tmp2.coeffs[i]>=12289)
      tmp2.coeffs[i]-=12289;
  }
  */
  //poly_ntt(&r2);
  poly tmp2;
  poly_add(&tmp2,&tmp1,&r2);
  for(i=0;i<1024;i++){
    if(pk.coeffs[i]==tmp2.coeffs[i])
      printf("yes ");
    else
      printf("%d %d ",pk.coeffs[i],tmp2.coeffs[i]);
  }
	return 0;
}

int tmp2(){
  poly_small x;
  int i;
  unsigned char b[768];
  /*
  for(i=0;i<1024;i++){
    x.coeffs[i]=0x0f;
  }
  poly_small_tobytes(b,&x);
  for(i=0;i<768/3;i++){
    if(b[3*i+0]==0xcf)
      printf("yes ");
    else
      printf("no ");
    if(b[3*i+1]==0xf3)
      printf("yes ");
    else
      printf("no ");
    if(b[3*i+2]==0x3c)
      printf("yes ");
    else
      printf("no ");
  }
  */
  for(i=0;i<768/3;i++){
    b[3*i+0]=0xcf;
    b[3*i+1]=0xf3;
    b[3*i+2]=0x3c;
  }
  poly_small_frombytes(&x,b);
  for(i=0;i<1024;i++){
    if(x.coeffs[i]==0x0f)
      printf("yes ");
    else
      printf("no ");
  }
  return 0;
}

int tmp4()
{
  poly sigma1,sigma2;
  poly_small v;
  unsigned char key1[128];
  unsigned char key2[128];
  int dis=2500;
  int i;
  /*
  for(i=0;i<1024/4;i++){
    sigma1.coeffs[4*i]=2345;
    sigma2.coeffs[4*i]=sigma1.coeffs[4*i]+dis;
    sigma1.coeffs[4*i+1]=4564;
    sigma2.coeffs[4*i+1]=sigma1.coeffs[4*i+1]+dis;
    sigma1.coeffs[4*i+2]=3455;
    sigma2.coeffs[4*i+2]=sigma1.coeffs[4*i+2]+dis;
    sigma1.coeffs[4*i+3]=6535;
    sigma2.coeffs[4*i+3]=sigma1.coeffs[4*i+3]+dis;
  }
  */
  sigma1.coeffs[0]=100;
  sigma2.coeffs[0]=sigma1.coeffs[0]+dis;
  for(i=1;i<1024;i++){
    sigma1.coeffs[i]=(sigma1.coeffs[i-1]+100)>=12289?(sigma1.coeffs[i-1]+100-12289):(sigma1.coeffs[i-1]+100);
    sigma2.coeffs[i]=(sigma1.coeffs[i]+dis)>=12289?(sigma1.coeffs[i]-dis):(sigma1.coeffs[i]+dis);
  }
  kccon(&v,&sigma1,key1);
  kcrec(key2,&sigma2,&v);
  for(i=0;i<128;i++){
    printf("%x %x ",key1[i],key2[i]);
    if(key1[i]!=key2[i]){
      printf("\n");
      int j;
      for(j=0;j<8;j++)
        printf("%d %d \n", sigma1.coeffs[8*i+j],sigma2.coeffs[8*i+j]);
    }
    //if(key1[i]==key2[i])
    //  printf("yes ");
    //else
   //   printf("no ");
  }
  return 0;
}

int tmp3(){
  unsigned char sendc0[PAK_SENDC0BYTES];
  unsigned char sends0[PAK_SENDS0BYTES];
  unsigned char sendc1[PAK_SENDC1BYTES];
  unsigned char statec[HASH_BYTES];
  //unsigned char states[HASH_BYTES];
  unsigned char pw[PW_BYTES]="abcdefgh";
  unsigned char sid[ID_BYTES]="12345678";
  unsigned char cid[ID_BYTES]="23456789";
  poly sk;
  unsigned char kc[32];
  unsigned char ks[32];
  //unsigned char keys[128];
  //unsigned char keyc[128];
  unsigned char k_[PAK_VERBYTES];
  pak_c0(sendc0,&sk,statec,pw,cid,sid);
  pak_s0(sends0,sendc0,k_,pw,sid);
  pak_c1(kc,sendc1,sends0,&sk,statec);
  pak_s1(ks,sendc1,k_);
  int i;
  for(i=0;i<32;i++){
    printf("%x %x ",kc[i],ks[i]);
    if(kc[i]!=ks[i])
      printf("error");
  }
  printf("finish");
  return 0;
}

int tmp5(){
  unsigned char statec[8]="abcdefgh";
  unsigned char kc[32];
  unsigned char ks[32];
  sha3256(kc,statec,8);
  sha3256(ks,statec,8);
  int i;
  for(i=0;i<32;i++){
    if(kc[i]!=ks[i])
      printf("error");
  }
  printf("finish");
  return 0;
}

int main()
{
  poly sigma1,sigma2;
  poly_small v;
  unsigned char key1[128];
  unsigned char key2[128];
  int dis=2000;
  int i;
  int j=0x0f;
  for(i=0;i<128;i++){
    key1[i]=j;
    j++;
  }
  /*
  for(i=0;i<1024/4;i++){
    sigma1.coeffs[4*i]=2345;
    sigma2.coeffs[4*i]=sigma1.coeffs[4*i]+dis;
    sigma1.coeffs[4*i+1]=4564;
    sigma2.coeffs[4*i+1]=sigma1.coeffs[4*i+1]+dis;
    sigma1.coeffs[4*i+2]=3455;
    sigma2.coeffs[4*i+2]=sigma1.coeffs[4*i+2]+dis;
    sigma1.coeffs[4*i+3]=6535;
    sigma2.coeffs[4*i+3]=sigma1.coeffs[4*i+3]+dis;
  }
  */
  sigma1.v[0]=100;
  sigma2.v[0]=sigma1.v[0]+dis;
  for(i=1;i<1024;i++){
    sigma1.v[i]=(sigma1.v[i-1]+100)>=12289?(sigma1.v[i-1]+100-12289):(sigma1.v[i-1]+100);
    sigma2.v[i]=(sigma1.v[i]+dis)>=12289?(sigma1.v[i]-dis):(sigma1.v[i]+dis);
  }
  uint8_t tmp=0;
  int pre[PARAM_N];
  for(i=0;i<PARAM_N;i++){
    if((i&0x7)==0)
        tmp=key1[i>>3];
    if((tmp>>7)==1)
        pre[i]=393280;
    else
        pre[i]=0;
    tmp=(tmp<<1);
    }

  akccon(&v,&sigma1,key1,pre);
  akcrec(key2,&sigma2,&v);
  for(i=0;i<128;i++){
    printf("%x %x ",key1[i],key2[i]);
    if(key1[i]!=key2[i]){
      printf("\n");
      int j;
      for(j=0;j<8;j++)
        printf("%d %d \n", sigma1.v[8*i+j],sigma2.v[8*i+j]);
    }
    //if(key1[i]==key2[i])
    //  printf("yes ");
    //else
   //   printf("no ");
  }
  return 0;
}