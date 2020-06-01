#include "key_consensus.h"
/*
void kccon(poly_small *v, const poly *sigma, unsigned char *key){
    //srand((int)time(0));
    int i;
    uint8_t k=0;
    for(i=0;i<PARAM_N;i++){
      //int16_t e=rand()&0x1;
      //uint16_t sigma_a=(sigma->coeffs[i]<<1)+e;
      uint16_t sigma_a=(sigma->coeffs[i]<<1);
      uint16_t v_;
      if(sigma_a<BETA){
          k=k<<1;
          v_=sigma_a;
      }
      else{
          k=k<<1|0x1;
          v_=sigma_a-BETA;
      }
      v->coeffs[i]=((uint32_t)v_<<6)/BETA;
      if((i&0x7)==7){
        key[i>>3]=k;
        k=0;
      }
    }
}
void kcrec(unsigned char *key, const poly *sigma, const poly_small *v){
    int i;
    uint8_t k=0;
    for(i=0;i<PARAM_N;i++){
      float r=(sigma->coeffs[i]<<1)/(float)BETA-(v->coeffs[i]+0.5)/(float)PARAM_G;
      if((r>=-1&&r<-0.5)||(r>=0.5&&r<1.5))
        k=(k<<1)|0x1;
      else
        k=k<<1;

      
     // int16_t k_=round(tmp-dis);
      //uint16_t k_t=k_+(((k_>>15)&1)<<1);
      //k=(k<<1)|(k_t&0x1);
      
      if((i&0x7)==7){
        key[i>>3]=k;
        k=0;
      }
    }
}

void akccon(poly_small *v, const poly *sigma, const unsigned char *key){
  int i;
  uint8_t tmp=0;
  for(i=0;i<PARAM_N;i++){
    int a1;
    if((i&0x7)==0)
        tmp=key[i>>3];
    if((tmp>>7)==1)
        a1=393280;
    else
        a1=0;
    tmp=(tmp<<1);
    uint16_t v_=(((uint32_t)sigma->coeffs[i]<<6)+a1)/(float)PARAM_Q+0.5;
    v->coeffs[i]=v_&0x3f;
  }
}

void akcrec(unsigned char *key, const poly *sigma, const poly_small *v){
    int i;
    uint8_t k=0;
    for(i=0;i<PARAM_N;i++){
      float r=v->coeffs[i]/(float)PARAM_G-sigma->coeffs[i]/(float)PARAM_Q;
      if((r>=-0.75&&r<-0.25)||(r>=0.25&&r<0.75))
        k=(k<<1)|0x1;
      else
        k=k<<1;

      if((i&0x7)==7){
        key[i>>3]=k;
        k=0;
      }
    }
}
*/
void kccon(poly_small *v, const poly *sigma, unsigned char *key){
    //srand((unsigned)time(NULL));
    int i,j;
    for(i=0;i<PARAM_N/8;i++){
      for(j=0;j<8;j++){
        //int8_t e=rand()&0x1;
        //uint16_t sigma_a=(sigma->coeffs[8*i+j]<<1)+e;
        uint16_t sigma_a=(sigma->coeffs[8*i+j]<<1);
        uint16_t v_;
        if(sigma_a<BETA){
            key[i]=key[i]<<1;
            v_=sigma_a;
        }
        else{
            key[i]=(key[i]<<1)|0x1;
            v_=sigma_a-BETA;
        }
        v->coeffs[8*i+j]=((uint32_t)v_<<6)/BETA;
        }
    }
}
void kcrec(unsigned char *key, const poly *sigma, const poly_small *v){
    int i,j;
    for(i=0;i<PARAM_N/8;i++){
      for(j=0;j<8;j++){
            float r=(sigma->coeffs[8*i+j]<<1)/(float)BETA-(v->coeffs[8*i+j]+0.5)/(float)PARAM_G;
            if((r>=-1.5&&r<-0.5)||(r>=0.5&&r<1.5))
              key[i]=(key[i]<<1)|0x1;
            else
              key[i]=key[i]<<1;
          }
      
      //int16_t k_=round(tmp-dis);
      //uint16_t k_t=k_+(((k_>>15)&1)<<1);
      //k=(k<<1)|(k_t&0x1);
    }
}
void akccon(poly_small *v, const poly *sigma, const unsigned char *key,const int *pre){
  int i;
  for(i=0;i<PARAM_N;i++){
    uint16_t v_=(((uint32_t)sigma->coeffs[i]<<6)+pre[i])/(float)PARAM_Q+0.5;
    v->coeffs[i]=v_&0x3f;
  }
}
void akcrec(unsigned char *key, const poly *sigma, const poly_small *v){
    int i,j;
    for(i=0;i<PARAM_N*BITS_M/8;i++){
      unsigned char y=0;
      for(j=0;j<8/BITS_M;j++)
      {
        float r=(v->coeffs[i*8+j]/(float)PARAM_G-sigma->coeffs[i*8+j]/(float)PARAM_Q)*PARAM_M;
        uint8_t x=(r<0)?(r-0.5):(r+0.5);
        //uint8_t x=1;
        //if(r<0)
        //  x=r-0.5;
        //else
        //  x=r+0.5;
        x=x%PARAM_M;
        //key[i]=(key[i]<<1)|(x&0x1);
        y=(y<<BITS_M)|(x);
        }
        key[i]=y;
    }
}

