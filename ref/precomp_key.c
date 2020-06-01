#include "randombytes.h"
#include "params_pak.h"
void precomp_key(unsigned char *key,int *pre){
    randombytes(key, PAK_KEYBYTES);
    for(i=0;i<PARAM_N;i++){
    if((i&0x7)==0)
        tmp=key[i>>3];
    if((tmp>>7)==1)
        pre[i]=393280;
    else
        pre[i]=0;
    tmp=(tmp<<1);
    }
}
