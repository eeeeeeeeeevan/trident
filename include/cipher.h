#pragma once


#include "types.h"
#include "config.h"
#include "hash_interface.h"

typedef __uint128_t bigint;
typedef unsigned char uchar;
typedef struct {
    ull counter;
    ull mask_idx;
    ull mask_map;
    uchar* memory_map;
    unsigned int position;
} memhard_t;


// cipher state
typedef struct {
    unsigned short sbox[ROUNDC][SBOXSIZE];
    unsigned short sbox_inverse[ROUNDC][SBOXSIZE];
    uchar pbox[ROUNDC][BLOCKSIZE];
    uchar key_schedule[KSBLOCKS][BLOCKSIZE];
    uchar counter_block[HASHOUTSIZE];
    unsigned short hash_block[HASHOUTSIZE/2]; 
    const hashes_t * hash_keys;
    memhard_t memhard;
} trident_cstate;

void trident_cycler (uchar output[64], const uchar input[64], const uchar input2[64], unsigned int selector, const hashes_t * keys);
void encblock (trident_cstate * state, uchar output[BLOCKSIZE], const uchar input[BLOCKSIZE], __uint128_t block_id);
void decrypt_block (trident_cstate * state, uchar output[BLOCKSIZE], const uchar input[BLOCKSIZE], __uint128_t block_id);
void finalcleanup (trident_cstate * state);
