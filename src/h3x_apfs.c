/* h3x_apfs - System Geometric Soundness. Author: Derek Hinch */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/h3x_format.h"
#define MAX_E 512
#define SAMP 8192
typedef struct {char name[128];float id,en,ent;uint32_t sz;int flag;char reason[64];} SE;
static void ctok(uint8_t a,uint8_t b,uint8_t t[8]){
    for(int i=0;i<4;i++){int ec=(a>>(7-2*i))&1,oc=(a>>(6-2*i))&1,en2=(b>>(7-2*i))&1,on=(b>>(6-2*i))&1;
        t[i]=(uint8_t)((ec+oc)-(en2+on)+2);t[4+i]=(uint8_t)((ec-oc)-(en2-on)+2);}}
static SE prof(const char *path,const char *nm){
    SE e;memset(&e,0,sizeof(e));strncpy(e.name,nm,127);
    FILE *f=fopen(path,"rb");if(!f)return e;
    fseek(f,0,SEEK_END);long s=ftell(f);fseek(f,0,SEEK_SET);e.sz=(uint32_t)s;
    size_t rs=(size_t)(s<SAMP?s:SAMP);uint8_t *buf=malloc(rs);
    size_t g=fread(buf,1,rs,f);fclose(f);if(g<64){free(buf);return e;}
    uint32_t d[5]={0},tot=0;float es2=0;
    for(size_t i=0;i+1<g;i++){uint8_t t[8];ctok(buf[i],buf[i+1],t);
        for(int j=0;j<8;j++){d[t[j]]++;tot++;es2+=fabsf((float)t[j]-2.0f);}}
    if(tot>0){e.id=(float)d[2]/tot;e.en=es2/tot;}
    free(buf);return e;}
static void scandir2(const char *dp,const char *sfx,SE *es,int *c,int mx){
    DIR *d2=opendir(dp);if(!d2)return;struct dirent *ent;
    while((ent=readdir(d2))&&*c<mx){if(ent->d_name[0]=='.')continue;
        if(sfx&&!strstr(ent->d_name,sfx))continue;
        char fp[512];snprintf(fp,511,"%s/%s",dp,ent->d_name);
        struct stat st;if(stat(fp,&st)!=0)continue;
        if(S_ISDIR(st.st_mode)){char bp[512];
            snprintf(bp,511,"%s/Contents/MacOS/%.*s",fp,(int)(strlen(ent->d_name)-5),ent->d_name);
            if(access(bp,R_OK)==0){es[*c]=prof(bp,ent->d_name);(*c)++;}}
        else if(S_ISREG(st.st_mode)&&st.st_size>64){
            es[*c]=prof(fp,ent->d_name);(*c)++;}}
    closedir(d2);}
static void chk(SE *es,int n,const char *cat,float idmin,float emax){
    for(int i=0;i<n;i++){if(es[i].sz==0)continue;
        if(es[i].id<idmin){es[i].flag=1;snprintf(es[i].reason,63,"LOW_ID");}
        if(es[i].en>emax+0.2f){es[i].flag=1;snprintf(es[i].reason,63,"HIGH_ENERGY");}
        if(strcmp(cat,"kext")==0&&es[i].id<0.42f){
            es[i].flag=1;snprintf(es[i].reason,63,"ENCRYPTED?");}}}
int main(int argc,char*argv[]){
    if(argc<2){fprintf(stderr,"h3x_apfs --scan-kexts|--scan-firmware|--scan-drivers|--full\n");return 1;}
    int dk=!strcmp(argv[1],"--scan-kexts")||!strcmp(argv[1],"--full");
    int df=!strcmp(argv[1],"--scan-firmware")||!strcmp(argv[1],"--full");
    int dd=!strcmp(argv[1],"--scan-drivers")||!strcmp(argv[1],"--full");
    printf("H3X SYSTEM GEOMETRIC SOUNDNESS\n\n");int ts=0,tf=0;
    if(dk){SE k[MAX_E];int n=0;
        scandir2("/System/Library/Extensions",".kext",k,&n,MAX_E);
        scandir2("/Library/Apple/System/Library/Extensions",".kext",k,&n,MAX_E);
        chk(k,n,"kext",0.70f,0.40f);
        printf("  %-28s %6s %4s %5s %s\n","Kext","Size","ID%","Enrgy","Status");
        for(int i=0;i<n&&i<25;i++)if(k[i].sz>0)
            printf("  %-28s%6uK %3.0f%% %5.2f %s\n",k[i].name,k[i].sz/1024,k[i].id*100,k[i].en,k[i].flag?k[i].reason:"OK");
        int fl=0;for(int i=0;i<n;i++)if(k[i].flag)fl++;
        printf("  Kexts: %d scanned, %d flagged\n\n",n,fl);ts+=n;tf+=fl;}
    if(df){SE fw[MAX_E];int n=0;
        scandir2("/usr/standalone/firmware/t302",".bin",fw,&n,MAX_E);
        chk(fw,n,"firmware",0.35f,0.90f);
        printf("  %-28s %6s %4s %5s %s\n","Firmware","Size","ID%","Enrgy","Status");
        for(int i=0;i<n&&i<15;i++)if(fw[i].sz>0)
            printf("  %-28s%6uK %3.0f%% %5.2f %s\n",fw[i].name,fw[i].sz/1024,fw[i].id*100,fw[i].en,fw[i].flag?fw[i].reason:"OK");
        int fl=0;for(int i=0;i<n;i++)if(fw[i].flag)fl++;
        printf("  Firmware: %d scanned, %d flagged\n\n",n,fl);ts+=n;tf+=fl;}
    if(dd){SE d3[MAX_E];int n=0;
        scandir2("/usr/libexec",NULL,d3,&n,40);scandir2("/usr/sbin",NULL,d3,&n,40);
        chk(d3,n,"system",0.60f,0.60f);
        printf("  %-28s %6s %4s %5s %s\n","Binary","Size","ID%","Enrgy","Status");
        for(int i=0;i<n&&i<25;i++)if(d3[i].sz>0)
            printf("  %-28s%6uK %3.0f%% %5.2f %s\n",d3[i].name,d3[i].sz/1024,d3[i].id*100,d3[i].en,d3[i].flag?d3[i].reason:"OK");
        int fl=0;for(int i=0;i<n;i++)if(d3[i].flag)fl++;
        printf("  System: %d scanned, %d flagged\n\n",n,fl);ts+=n;tf+=fl;}
    printf("TOTAL: %d scanned, %d flagged\n",ts,tf);return tf>0?1:0;}
