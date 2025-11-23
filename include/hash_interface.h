#pragma once

#include "types.h"
#include "config.h"

typedef uint uint;
typedef unsigned long long ull;
typedef unsigned char uchar;
typedef const unsigned char cuchar;
// TKSIZE - MKEYSIZE
typedef struct {
    uchar blake2b_key[BLAKESIZE];
    uchar sha512_key[SHA512SIZE];
    uchar sha512_ext_key[SHAEXTSIZE];
    uchar sha3_key[SHA3SIZE];
    uchar sha3_ext_key[SHA3EXTSIZE];
    uchar whirlpool_key[WPKEYSIZE];
} hashes_t;


void tridentblake (uchar output[64], cuchar input[64],  cuchar * input2, cuchar key[BLAKESIZE]);
void tridentsha (uchar output[64], cuchar input[64],  cuchar * input2, cuchar key[SHA512SIZE], cuchar ext_key[SHAEXTSIZE]);
void tridentshat (uchar output[64], cuchar input[64],  cuchar * input2, cuchar key[SHA3SIZE],cuchar ext_key[SHA3EXTSIZE]);
void tridentwp (uchar output[64], cuchar input[64],  cuchar * input2, cuchar key[WPKEYSIZE]);
// chainer functions
void tridenthasher (uchar output[64], cuchar input[64],   cuchar input2[64], uint selector, const hashes_t * keys);
// use comb selector with selection idx
void trident_cycler (uchar output[64], cuchar input[64],   cuchar input2[64], uint selector,  const hashes_t * keys);
