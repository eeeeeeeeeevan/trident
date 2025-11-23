#pragma once

#include "cipher.h"
#include "hash_interface.h"
#include <stdio.h>
#define TRIDENT_TROUNDS 12
#define trident_KSBLOCKS (TRIDENT_TROUNDS + 1)

typedef struct {
    unsigned short sbox[SBOXSIZE];
    unsigned short sbox_inverse[SBOXSIZE];
    unsigned char pbox[BLOCKSIZE];
    unsigned char key_schedule[trident_KSBLOCKS][BLOCKSIZE];
    unsigned char counter_block[HASHOUTSIZE];
    unsigned short hash_block[HASHOUTSIZE/2]; 
    const hashes_t* hash_keys;
    memhard_t memhard;
} trident_state_curr;

currstat trident_init (
    trident_state_curr* state, 
    const unsigned char iv[MKEYSIZE], 
    const unsigned char master_key[MKEYSIZE], 
    const hashes_t* hash_keys, 
    double cpubias, 
    unsigned int memwork
);

void trident_enc (
    trident_state_curr* state, 
    unsigned char output[BLOCKSIZE], 
    const unsigned char input[BLOCKSIZE], 
    __uint128_t block_id
);

void trident_dec (
    trident_state_curr* state,
    unsigned char output[BLOCKSIZE], 
    const unsigned char input[BLOCKSIZE],
     __uint128_t block_id
);

void trident_cleanup (trident_state_curr* state);
