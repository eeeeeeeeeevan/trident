#pragma once

#include "types.h"
#include "config.h"

typedef uint uint;
typedef unsigned long long ull;
typedef unsigned char byte;
typedef const unsigned char cuchar;
// TKSIZE - MKEYSIZE
typedef struct {
    byte blake2b_key[BLAKESIZE];
    byte sha512_key[SHA512SIZE];
    byte sha512_ext_key[SHAEXTSIZE];
    byte sha3_key[SHA3SIZE];
    byte sha3_ext_key[SHA3EXTSIZE];
    byte whirlpool_key[WPKEYSIZE];
} hashes_t;


void tridentblake (byte output[64], cuchar input[64],  cuchar * input2, cuchar key[BLAKESIZE]);
void tridentsha (byte output[64], cuchar input[64],  cuchar * input2, cuchar key[SHA512SIZE], cuchar ext_key[SHAEXTSIZE]);
void tridentshat (byte output[64], cuchar input[64],  cuchar * input2, cuchar key[SHA3SIZE],cuchar ext_key[SHA3EXTSIZE]);
void tridentwp (byte output[64], cuchar input[64],  cuchar * input2, cuchar key[WPKEYSIZE]);
// chainer functions
void tridenthasher (byte output[64], cuchar input[64],   cuchar input2[64], uint selector, const hashes_t * keys);
// use comb selector with selection idx
void trident_cycler (byte output[64], cuchar input[64],   cuchar input2[64], uint selector,  const hashes_t * keys);
