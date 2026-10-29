/* host check: gateway memops vs reference byte loops over sizes and alignments */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
void *gw_memcpy(void *restrict, const void *restrict, size_t);
void *gw_memset(void *, int, size_t);
int main(void){
  static uint8_t a[4200], b[4200], r[4200]; unsigned long checks=0;
  srand(1);
  for(int i=0;i<4200;i++) a[i]=rand();
  for(size_t n=0;n<=1608;n+=(n<64?1:37)) for(int so=0;so<8;so++) for(int doff=0;doff<8;doff++){
    memset(b,0xAA,sizeof b); memset(r,0xAA,sizeof r);
    for(size_t k=0;k<n;k++) r[doff+k]=a[so+k];
    if(gw_memcpy(b+doff,a+so,n)!=b+doff || memcmp(b,r,sizeof b)) {printf("memcpy FAIL n=%zu so=%d do=%d\n",n,so,doff);return 1;}
    memset(b,0x55,sizeof b); memset(r,0x55,sizeof r);
    for(size_t k=0;k<n;k++) r[doff+k]=(uint8_t)(so*31+7);
    if(gw_memset(b+doff,so*31+7,n)!=b+doff || memcmp(b,r,sizeof b)) {printf("memset FAIL n=%zu do=%d\n",n,doff);return 1;}
    checks+=2;
  }
  printf("memops host check PASS %lu cases\n",checks); return 0;
}
