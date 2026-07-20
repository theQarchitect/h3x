/*
 * h3x_sig — Boundary-Aware Geometric Signatures (SGH5 Walk + BF64)
 * Author: Derek Hinch
 * Build: cc -O3 -o h3x_sig h3x_sig.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../include/h3x_format.h"

#define WARMUP 200
#define WINDOW 32
#define MAX_BOUNDS 2048
#define PHI 0.6180339887498949

typedef enum { B_STRUCTURAL, B_CONSTRAINED, B_EDITABLE } BType;
static const char *btype_name[] = {"STRUCTURAL","CONSTRAINED","EDITABLE"};

typedef struct {
    uint32_t start, end;
    BType type;
    double accumulator;
    uint64_t orbit_hash;
    float identity_density;
    float avg_confidence;
} BoundSegment;

typedef struct {
    uint32_t n_segments;
    uint32_t file_size;
    double global_acc;
    uint64_t global_orbit;
    BoundSegment segs[MAX_BOUNDS];
} BoundSet;

static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for (int i=0;i<4;i++){
        int ec=(a>>(7-2*i))&1,oc=(a>>(6-2*i))&1,en=(b>>(7-2*i))&1,on=(b>>(6-2*i))&1;
        tok[i]=(uint8_t)((ec+oc)-(en+on)+2); tok[4+i]=(uint8_t)((ec-oc)-(en-on)+2);
    }
}

typedef struct { uint32_t bg[8][5][5]; uint8_t prev[8]; uint32_t n; } Pred;
static void pred_init(Pred *p){memset(p,0,sizeof(Pred));for(int c=0;c<8;c++){p->prev[c]=2;for(int i=0;i<5;i++)for(int j=0;j<5;j++)p->bg[c][i][j]=1;}}
static float pred_feed(Pred *p, const uint8_t tok[8]){
    float conf=0;
    if(p->n>=WARMUP){for(int c=0;c<8;c++){uint32_t*row=p->bg[c][p->prev[c]];uint32_t tot=0,best=0;for(int j=0;j<5;j++){tot+=row[j];if(row[j]>best)best=row[j];}if(tot>0)conf+=(float)best/tot;}conf/=8.0f;}
    for(int c=0;c<8;c++){p->bg[c][p->prev[c]][tok[c]]++;p->prev[c]=tok[c];}p->n++;return conf;
}

static const double SGH5_ROT[5] = {-1.0, -0.5, PHI, 0.5, 1.0};
typedef struct { double acc; double phase; uint64_t orbit; uint32_t n_tok; uint32_t n_id; } Acc;
static void acc_init(Acc *a){a->acc=1.0;a->phase=0;a->orbit=0xcbf29ce484222325ULL;a->n_tok=0;a->n_id=0;}
static void acc_feed(Acc *a, uint8_t tok){
    a->acc = a->acc * SGH5_ROT[tok&7] + sin(a->phase);
    a->phase += 0.01*(tok+1); if(a->phase>6.2831853) a->phase-=6.2831853;
    a->orbit ^= (uint64_t)tok; a->orbit *= 0x100000001b3ULL;
    a->n_tok++; if(tok==2) a->n_id++;
}

static BoundSet compute_bound_set(const uint8_t *data, size_t n) {
    BoundSet bs; memset(&bs, 0, sizeof(bs));
    bs.file_size = (uint32_t)n;

    /* Pass 1: find boundaries */
    Pred pred; pred_init(&pred);
    float *scores = calloc(n, sizeof(float));
    for(size_t i=0;i+1<n;i++){uint8_t tok[8];compute_tokens(data[i],data[i+1],tok);scores[i]=pred_feed(&pred,tok);}
    float *sm = calloc(n, sizeof(float));
    for(size_t i=0;i<n-1;i++){float s=0;int c=0;for(int w=-WINDOW/2;w<=WINDOW/2;w++){int idx=(int)i+w;if(idx>=0&&idx<(int)(n-1)){s+=scores[idx];c++;}}sm[i]=c>0?s/c:0;}

    uint32_t starts[MAX_BOUNDS]; BType types[MAX_BOUNDS]; int nb=0;
    BType cur = sm[0]>0.7f?B_STRUCTURAL:sm[0]>0.5f?B_CONSTRAINED:B_EDITABLE;
    starts[0]=0; types[0]=cur;
    for(size_t i=1;i<n-1&&nb<MAX_BOUNDS-1;i++){
        BType t=sm[i]>0.7f?B_STRUCTURAL:sm[i]>0.5f?B_CONSTRAINED:B_EDITABLE;
        if(t!=cur){nb++; starts[nb]=(uint32_t)i; types[nb]=t; cur=t;}
    }
    nb++;
    free(scores); free(sm);

    /* Global acc */
    Acc ga; acc_init(&ga);
    for(size_t i=0;i+1<n;i++){uint8_t tok[8];compute_tokens(data[i],data[i+1],tok);for(int j=0;j<8;j++)acc_feed(&ga,tok[j]);}
    bs.global_acc=ga.acc; bs.global_orbit=ga.orbit;

    /* Pass 2: per-segment accumulators */
    bs.n_segments = nb < MAX_BOUNDS ? nb : MAX_BOUNDS;
    for(int seg=0;seg<(int)bs.n_segments;seg++){
        uint32_t start=starts[seg];
        uint32_t end=(seg+1<(int)bs.n_segments)?starts[seg+1]:(uint32_t)n;
        Acc sa; acc_init(&sa);
        for(uint32_t i=start;i+1<end;i++){uint8_t tok[8];compute_tokens(data[i],data[i+1],tok);for(int j=0;j<8;j++)acc_feed(&sa,tok[j]);}
        bs.segs[seg]=(BoundSegment){start,end,types[seg],sa.acc,sa.orbit,
            sa.n_tok>0?(float)sa.n_id/sa.n_tok:0, 0};
    }
    return bs;
}

static float bound_set_similarity(const BoundSet *a, const BoundSet *b) {
    int matches=0, compared=0;
    int na=a->n_segments<64?a->n_segments:64;
    int nb2=b->n_segments<64?b->n_segments:64;
    for(int i=0;i<na;i++){
        float best=0;
        for(int j=0;j<nb2;j++){
            if(abs((int)a->segs[i].start-(int)b->segs[j].start)>(int)(a->file_size*0.2)) continue;
            if(a->segs[i].type!=b->segs[j].type) continue;
            float orbit_m=(a->segs[i].orbit_hash==b->segs[j].orbit_hash)?1.0f:0.0f;
            float acc_s=(float)(1.0/(1.0+fabs(a->segs[i].accumulator-b->segs[j].accumulator)));
            float id_s=1.0f-fabsf(a->segs[i].identity_density-b->segs[j].identity_density);
            float s=orbit_m*0.5f+acc_s*0.3f+id_s*0.2f;
            if(s>best) best=s;
        }
        if(best>0.4f) matches++;
        compared++;
    }
    return compared>0?(float)matches/compared:0;
}

int main(int argc, char *argv[]) {
    if(argc<3){
        fprintf(stderr,"h3x_sig — Boundary-Aware Geometric Signatures\n");
        fprintf(stderr,"  %s <file> --sign\n",argv[0]);
        fprintf(stderr,"  %s <file_a> --blame <file_b>\n",argv[0]);
        fprintf(stderr,"  %s <file_a> --similarity <file_b>\n",argv[0]);
        fprintf(stderr,"  %s <file> --yara-rule <name>\n",argv[0]);
        return 1;
    }
    FILE *f=fopen(argv[1],"rb");if(!f){perror("fopen");return 1;}
    fseek(f,0,SEEK_END);long fsize=ftell(f);fseek(f,0,SEEK_SET);
    uint8_t *data=malloc(fsize);fread(data,1,fsize,f);fclose(f);
    const char *mode=argv[2];

    if(!strcmp(mode,"--sign")){
        BoundSet bs=compute_bound_set(data,(size_t)fsize);
        printf("H3X Bound Set Signature (%s, %ld bytes)\n",argv[1],fsize);
        printf("  Global: acc=%.6f orbit=%016llx segments=%u\n\n",
            bs.global_acc,(unsigned long long)bs.global_orbit,bs.n_segments);
        printf("  %8s %8s %12s %12s %16s %5s\n","Start","End","Type","Accumulator","Orbit","ID%");
        printf("  ────────────────────────────────────────────────────────────────────\n");
        for(uint32_t i=0;i<bs.n_segments;i++){
            BoundSegment *s=&bs.segs[i];
            printf("  0x%06X 0x%06X %12s %12.4f %016llx %4.0f%%\n",
                s->start,s->end,btype_name[s->type],s->accumulator,
                (unsigned long long)s->orbit_hash,s->identity_density*100);
        }
        free(data);return 0;
    }

    if(!strcmp(mode,"--similarity")&&argc>=4){
        FILE *fb=fopen(argv[3],"rb");if(!fb){perror("B");free(data);return 1;}
        fseek(fb,0,SEEK_END);long bs2=ftell(fb);fseek(fb,0,SEEK_SET);
        uint8_t *db=malloc(bs2);fread(db,1,bs2,fb);fclose(fb);
        BoundSet a=compute_bound_set(data,(size_t)fsize);
        BoundSet b=compute_bound_set(db,(size_t)bs2);
        printf("%.4f\n",bound_set_similarity(&a,&b));
        free(data);free(db);return 0;
    }

    if(!strcmp(mode,"--blame")&&argc>=4){
        FILE *fb=fopen(argv[3],"rb");if(!fb){perror("B");free(data);return 1;}
        fseek(fb,0,SEEK_END);long bs2=ftell(fb);fseek(fb,0,SEEK_SET);
        uint8_t *db=malloc(bs2);fread(db,1,bs2,fb);fclose(fb);
        BoundSet a=compute_bound_set(data,(size_t)fsize);
        BoundSet b=compute_bound_set(db,(size_t)bs2);
        float sim=bound_set_similarity(&a,&b);
        printf("H3X Blame (%s vs %s)\n",argv[1],argv[3]);
        printf("  Similarity: %.1f%%\n  Divergent segments:\n",sim*100);
        int nc=a.n_segments<b.n_segments?a.n_segments:b.n_segments;
        int div=0;
        for(int i=0;i<nc;i++){
            if(a.segs[i].orbit_hash!=b.segs[i].orbit_hash){
                printf("    0x%06X %s orbit: %016llx vs %016llx\n",
                    a.segs[i].start,btype_name[a.segs[i].type],
                    (unsigned long long)a.segs[i].orbit_hash,
                    (unsigned long long)b.segs[i].orbit_hash);
                div++;
            }
        }
        if(!div) printf("    (none)\n");
        printf("  %d/%d segments diverged\n",div,nc);
        free(data);free(db);return 0;
    }

    if(!strcmp(mode,"--yara-rule")&&argc>=4){
        BoundSet bs=compute_bound_set(data,(size_t)fsize);
        printf("import \"h3x\"\n\nrule %s {\n  meta:\n    author=\"h3x_sig\"\n",argv[3]);
        printf("    h3x_global_acc=\"%.8f\"\n",bs.global_acc);
        printf("  condition:\n    h3x.bound_set_match([\n");
        int p=0;
        for(uint32_t i=0;i<bs.n_segments&&p<10;i++){
            if(bs.segs[i].identity_density<0.95f){
                printf("      {off:0x%X,type:\"%s\",orbit:0x%llx}%s\n",
                    bs.segs[i].start,btype_name[bs.segs[i].type],
                    (unsigned long long)bs.segs[i].orbit_hash,p<9?",":"");
                p++;
            }
        }
        printf("    ], %d)\n}\n",p>3?p/2:2);
        free(data);return 0;
    }

    fprintf(stderr,"Unknown: %s\n",mode);free(data);return 1;
}
