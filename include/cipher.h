#pragma once


#include "types.h"
#include "config.h"
#include "hash_interface.h"

typedef __uint128_t bigint;
typedef unsigned char byte;
typedef struct {
    ull counter;
    ull mask_idx;
    ull mask_map;
    byte* memory_map;
    unsigned int position;
} memhard_t;


// cipher state
typedef struct {
    unsigned short sbox[ROUNDC][SBOXSIZE];
    unsigned short sbox_inverse[ROUNDC][SBOXSIZE];
    byte pbox[ROUNDC][BLOCKSIZE];
    byte key_schedule[KSBLOCKS][BLOCKSIZE];
    byte counter_block[HASHOUTSIZE];
    unsigned short hash_block[HASHOUTSIZE/2]; 
    const hashes_t * hash_keys;
    memhard_t memhard;
} trident_cstate;

void trident_cycler (byte output[64], const byte input[64], const byte input2[64], unsigned int selector, const hashes_t * keys);
void encblock (trident_cstate * state, byte output[BLOCKSIZE], const byte input[BLOCKSIZE], __uint128_t block_id);
void decrypt_block (trident_cstate * state, byte output[BLOCKSIZE], const byte input[BLOCKSIZE], __uint128_t block_id);
void finalcleanup (trident_cstate * state);
