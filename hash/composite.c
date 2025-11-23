#include "hash_interface.h"
#include <stdlib.h>
#include <string.h>
// a bunch of  wrappers
typedef unsigned int uint;
typedef unsigned char uchar;
typedef const unsigned char cuchar;

#define HASH_COUNT 4
#define ZERO_C (HASH_COUNT * (HASH_COUNT - 1))        
#define ONE_C (ZERO_C * (ZERO_C - 1))   
#define CCOUNTTOTAL (ONE_C * (ONE_C - 1))   

typedef void (*hash_func_t)(uchar*, const uchar*, const uchar*, const hashes_t*);

static
void bl2b (uchar* out, const uchar* in, const uchar * in2, const hashes_t * keys)
{
    tridentblake(out, in, in2, keys->blake2b_key);
}

static 
void sha (uchar* out, const uchar* in, const uchar * in2, const hashes_t * keys)
{
    tridentsha(out, in, in2, keys->sha512_key, keys->sha512_ext_key);
}

static 
void shat (uchar* out, const uchar* in, const uchar * in2, const hashes_t * keys)
{
    tridentshat(out, in, in2, keys->sha3_key, keys->sha3_ext_key);
}

static 
void whirlpool (uchar* out, const uchar* in, const uchar * in2, const hashes_t * keys)
{
    tridentwp(out, in, in2, keys->whirlpool_key);
}

static const 
hash_func_t hash_functions[HASH_COUNT] = {
    bl2b,
    sha,
    shat,
    whirlpool 
};


static 
void section0 (
    uchar output[64], 
    cuchar input[64], 
    cuchar input2[64],
    uint selectidx, 
    const hashes_t * keys)
{
    uchar o1[64], o2[64];
    uint x = selectidx / (HASH_COUNT - 1);
    uint y = selectidx % (HASH_COUNT - 1);    if (y >= x) y++;
    
    hash_functions[x](o1, input, input2, keys);
    hash_functions[y](o2, input, o1, keys);

   
    for (uint i = 0; i < 64; i++) {
        output[i] = o1[i] ^ o2[i];
    }
}


static 
void section1 (
    uchar output[64], 
    cuchar input[64], 
    cuchar input2[64],
    uint selectidx, 
    const hashes_t * keys
)
{
    uchar o1[64], o2[64];

   
    uint x = selectidx / (ZERO_C - 1);
    uint y = selectidx % (ZERO_C - 1);
    if (y >= x) y++;

   
    section0(o1, input, input2, x, keys);
    section0(o2, input, o1, y, keys);

   
    for (uint i = 0; i < 64; i++) {
        output[i] = o1[i] ^ o2[i];
    }
}


static 
void combo2 (
    uchar output[64], 
    cuchar input[64], 
    cuchar input2[64],
    uint selectidx, 
    const hashes_t * keys
)
{
    uchar o1[64], o2[64];

   
    uint x = selectidx / (ONE_C - 1);
    uint y = selectidx % (ONE_C - 1);
    if (y >= x) y++;

   
    section1(o1, input, input2, x, keys);
    section1(o2, input, o1, y, keys);

   
    for (uint i=0; i<64; i++) {
        output[i] = o1[i] ^ o2[i];
    }
}

void tridenthasher (
    uchar output[64], 
    cuchar input[64],
    cuchar input2[64], 
    uint selectidx,
    const hashes_t * keys
)
{
   
    static const uint selections[24] = {
        7, 10, 15, 20, 25, 28, 40, 43, 46, 52, 56, 60,
        71, 75, 79, 85, 88, 91, 103, 106, 111, 116, 121, 124
    };

    if (selectidx >= 24) selectidx = 0;
    section1(output, input, input2, selections[selectidx], keys);
}

void trident_cycler (
    uchar output[64], 
    cuchar input[64],
    cuchar input2[64], 
    uint selectidx,
    const hashes_t * keys
)
{
    combo2(output, input, input2, selectidx, keys);
}

