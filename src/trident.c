#include "trident.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
typedef unsigned int unint;
#define CCOUNTTOTAL 17292
#define POPCOUNT(x) __builtin_popcount(x)
#define rotator(a, b) a=a<<b|a>>(128-b) //bitrot

const bool DEBUGMODE = false;
static 
void xorblocks (unsigned char* restrict dest, const unsigned char* restrict src, unint length)
{
    for (unint i = 0; i < length; i++) {
        dest[i] ^= src[i];
    }
}
// useless shit 
//  __attribute__((__deprecated__))
static inline 
void trident_debug_printblock (const unsigned short block[16])
{
    if (!DEBUGMODE) return;
    for (unint i = 0; i < 16; i++) {
        printf("%04x ", block[i]);
    }
    printf("\n");
}

//  __attribute__((__deprecated__))
static inline 
void trident_debug_print(const char* msg) 
{
    if (!DEBUGMODE) return;
    printf("[debug]: %s\n", msg);
}
// step into the next state of the rng
static unsigned 
short rng_next (trident_state_curr* state)
{
    if (state->memhard.position >= BLOCKSIZE / 2) {
        state->memhard.position = 0;
        
        ull index_xor = state->memhard.counter & 7;
        ull index_map = state->memhard.counter & state->memhard.mask_idx;
        // next block
        state->memhard.counter++;

        unsigned char* xorptr = (unsigned char*)state->hash_block;
        ull xor_q, map_q;
        memcpy(&xor_q, &xorptr[index_xor * 8], 8);
        memcpy(&map_q, &state->memhard.memory_map[index_map * 8], 8);
        ull rng = (xor_q ^ map_q) & state->memhard.mask_map; 
        // printf("[debug]: %llu\n", rng);

        xorblocks(xorptr, &state->memhard.memory_map[rng], HASHOUTSIZE);

        if (!(state->memhard.counter & 1023)) {
            tridenthasher(
                (unsigned char*)state->hash_block,
                (unsigned char*)state->hash_block,
                state->counter_block,
                map_q % 24,
                state->hash_keys
            );
        }
    }

    return state->hash_block[state->memhard.position++];
}

static unsigned 
short boxrng (trident_state_curr* state, unsigned short bound)
{
    unsigned short mask = bound - 1;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask + 1;

    unsigned short result;
    do {
        result = rng_next(state) & mask;
    } while (result >= bound);

    return result;
}

static 
currstat init_memhard (trident_state_curr* state, unint memwork)
{
    const ull msize = 1ULL << memwork;
    const ull bc = msize / HASHOUTSIZE;

    unsigned char* map = malloc(msize+HASHOUTSIZE);
    if (!map) return ERRORALLOC;

    ull keyedselect = 0;
    for (unint i=0; i<8; i++) {
        ull temp;
        memcpy(&temp, &state->counter_block[i * 8], 8);
        keyedselect ^= temp;
    }

    trident_cycler(
        map, 
        (unsigned char*)state->hash_block, 
        state->counter_block, 
        keyedselect % CCOUNTTOTAL, 
        state->hash_keys
    );

    for (ull i = 1; i < bc + 1; i++) trident_cycler(&map[i * HASHOUTSIZE], &map[(i - 1) * HASHOUTSIZE], (unsigned char*)state->hash_block, (keyedselect + i) % CCOUNTTOTAL, state->hash_keys);
    // cycle hashes fully again for fblock
    trident_cycler(
        (unsigned char*)state->hash_block, 
        &map[msize], 
        (unsigned char*)state->hash_block, 
        keyedselect % CCOUNTTOTAL, 
        state->hash_keys
    );

    // state finalizer
    // state->memhard.mask_idx = (msize / 8);
    state->memhard.mask_idx = (msize / 8) - 1;
    state->memhard.mask_map = msize - 1;
    state->memhard.counter = 0;
    state->memhard.position = 0;
    state->memhard.memory_map = map;

    return SUCCESS;
}

static 
int sbox_noswaps (const unsigned short sbox[SBOXSIZE], unint index)
{
    for (unint j=0; j<=index; j++) {
        unint pop = POPCOUNT(sbox[j] ^ index);
        if (pop >= 7 && pop <= 9) {
            return 0; 
        }
    }
    return 1; 
}

static void
sbox_repair (trident_state_curr* state, unsigned short sbox[SBOXSIZE], unint n)
{
    for (unint i=0; i<=n; i++) {
        while (1) {
            unint j = boxrng(state, SBOXSIZE - n - 2) + 1;
            FSWAP(unsigned short, sbox[i], sbox[j]);

            unint pi = POPCOUNT(sbox[i] ^ i);
            unint pj = POPCOUNT(sbox[j] ^ j);

            if (pi<7 || pi>9 || pj<7 || pj>9) {
                // s-box isnt fulfilled
                FSWAP(unsigned short, sbox[i], sbox[j]); 
            } else {
                break; 
            }
        }
    }
}

static 
void shuffle_sbox (trident_state_curr* state, unsigned short sbox[SBOXSIZE])
{
    for (unint i=SBOXSIZE-1; i>0; i--) {
        while (1) {
            unint j = boxrng(state, i);
            FSWAP(unsigned short, sbox[i], sbox[j]);

            unint pop = POPCOUNT(sbox[i] ^ i);

            if (pop <7 || pop > 9) {
                if (sbox_noswaps(sbox, i)) {
                    sbox_repair(state, sbox, i);
                    return;
                }
            } else {
                break; 
            }
        }
    }

    unint p0 = POPCOUNT(sbox[0]);
    if (p0 < 7 || p0 > 9) sbox_repair(state, sbox, 0);
    
}

static inline 
void shuffle_pbox (trident_state_curr* state, unsigned char pbox[16])
{
    for (unint i=15; i>0; i--) {
        unint j = boxrng(state, i);
        FSWAP(unsigned char, pbox[i], pbox[j]);
    }
}

static inline 
void sbox_init (trident_state_curr* state)
{
    for (unint i=0; i<SBOXSIZE; i++) state->sbox[i] = i;
    shuffle_sbox(state, state->sbox);
}

static inline 
void sboxinv_init (trident_state_curr* state)
{
    for (unint i=0; i<SBOXSIZE; i++) state->sbox_inverse[state->sbox[i]] = i;
    
}

static inline 
void pbox_init (trident_state_curr* state)
{
    for (unint i=0; i<BLOCKSIZE; i++) {
        state->pbox[i] = i;
    }
    shuffle_pbox(state, state->pbox);
}

static 
void keysc_init (trident_state_curr* state, const unsigned char master_key[MKEYSIZE], const unsigned char iv[MKEYSIZE], ull cpu_work)
{
    unsigned char key_iv[256];
    memcpy(&key_iv[0], master_key, MKEYSIZE);
    memcpy(&key_iv[128], iv, MKEYSIZE);

    const unint key_blocks = trident_KSBLOCKS;
    const unint key_init = MACMIN(8, key_blocks);

    for (unint k = 0; k < key_init; k++) {
        memcpy(state->key_schedule[k], &key_iv[k * BLOCKSIZE], BLOCKSIZE);
    }

    if (key_blocks > 8) {
        unsigned char hash_block[HASHOUTSIZE];
        memset(hash_block, 0xA5, HASHOUTSIZE);
        // key expansion
        for (unint k=0; k<key_blocks-8; k++) {
            tridenthasher(
                hash_block, 
                hash_block, 
                &master_key[0], 
                boxrng(state, 23), 
                state->hash_keys
            );
            tridenthasher(
                hash_block, 
                hash_block, 
                &master_key[64],
                boxrng(state, 23), 
                state->hash_keys
            );
            tridenthasher(
                hash_block, 
                hash_block, 
                &iv[0],
                boxrng(state, 23), 
                state->hash_keys
            );
            tridenthasher(
                hash_block, 
                hash_block, 
                &iv[64],
                boxrng(state, 23), 
                state->hash_keys
            );

            memcpy(state->key_schedule[k + 8], hash_block, BLOCKSIZE);
        }
    }
    
    for (ull r=0; r<cpu_work; r++) {
        for (unint k=0; k<key_blocks; k++) {
            for (unint i=0; i<16; i++) {
                unsigned short x, y;
                memcpy(&x, &state->key_schedule[k][i * 2], 2);
                y = rng_next(state);
                x ^= y;
                memcpy(&state->key_schedule[k][i * 2], &x, 2);
            }
        }
    }
}

currstat trident_init (trident_state_curr* state, const unsigned char iv[MKEYSIZE], const unsigned char master_key[MKEYSIZE], const hashes_t* hash_keys, double cpubias, unint memwork)
{
    if (!state || !iv || !master_key || !hash_keys) return ERRINVPARAM;
    if (memwork < MINMEM || memwork > MAXMEM)  return ERRINVPARAM;
    if (cpubias < MINCPUBIAS || cpubias > MAXCPUBIAS) return ERRINVPARAM;
    
    ull keyedselect = 0;
    for (unint i=0; i<16; i++) {
        ull temp;
        memcpy(&temp, &master_key[i * 8], 8);
        keyedselect ^= temp;
    }

    state->hash_keys = hash_keys;

    tridenthasher(
        state->counter_block,
        &master_key[0],
        &iv[0],
        keyedselect % 24, 
        hash_keys
    );

    tridenthasher(
        (unsigned char*)state->hash_block,
        &master_key[64],
        &iv[64], 
        keyedselect % 24, 
        hash_keys
    );

    const ull cpu_work = ((1ULL << memwork) / 16) * cpubias;

    currstat status = init_memhard(state, memwork);
    if (status != SUCCESS) {
        return status;
    }

    sbox_init(state);
    sboxinv_init(state);
    pbox_init(state);
    keysc_init(state, master_key, iv, cpu_work);

    tridenthasher(state->counter_block, state->counter_block,  (unsigned char*)state->hash_block,  boxrng(state, 23), hash_keys);

    free(state->memhard.memory_map);
    memset((unsigned char*)state->hash_block, 0, HASHOUTSIZE);
    memset(&state->memhard, 0, sizeof(memhard_t));

    return SUCCESS;
}

static void
substitute (unsigned short block[16], const unsigned short sbox[SBOXSIZE])
{
    for (unint i = 0; i < 16; i++) {
        block[i] = sbox[block[i]];
    }
}

// stupid fucking diffusion 
static 
void permute (unsigned short block[16], const unsigned char pbox[BLOCKSIZE])
{
    bigint pht[2];
    memcpy(pht, block, BLOCKSIZE);
    // ph transform "diffusion"
    #define ptrans(n1, n2) do {           \
        bigint n1_new = n1 + n2;             \
        bigint n2_new = n1 + (2 * n2);       \
        n1 = n1_new; n2 = n2_new;              \
    } while(0)


    ptrans(pht[0], pht[1]);
    rotator(pht[0], 56);
    ptrans(pht[0], pht[1]);
    rotator(pht[0], 29);

    #undef ptrans
    // FUCK
    #undef rotator

    for (unint i = 0; i < BLOCKSIZE; i++) {
        ((unsigned char*)block)[pbox[i]] = ((const unsigned char*)pht)[i];
    }
}

static 
void invperm (unsigned short block[16], const unsigned char pbox[BLOCKSIZE])
{
    bigint pht[2];

    for (unint i=0; i<BLOCKSIZE; i++) {
        ((unsigned char*)pht)[i] = ((const unsigned char*)block)[pbox[i]];
    }
    // inverse
    #define ptransinv(n1, n2) do {        \
        bigint n1_new = (2 * n1) - n2;      \
        bigint n2_new = n2 - n1;            \
        n1 = n1_new; n2 = n2_new;              \
    } while(0)

    #define ROR128(v, c) v = v >> c | v << (128 - c)

    ROR128(pht[0], 29);
    ptransinv(pht[0], pht[1]);
    ROR128(pht[0], 56);
    ptransinv(pht[0], pht[1]);

    #undef ptransinv
    #undef ROR128

    memcpy(block, pht, BLOCKSIZE);
}

void trident_enc (trident_state_curr* state, unsigned char output[BLOCKSIZE], const unsigned char input[BLOCKSIZE], bigint block_id)
{
    unsigned short block[16];
    memcpy(block, input, BLOCKSIZE);

    bigint* bptr = (bigint*)block;
    bptr[0] ^= block_id;

    for (unint r=0; r<TRIDENT_TROUNDS; r++) {
        xorblocks((unsigned char*)block, state->key_schedule[r], BLOCKSIZE);
        substitute(block, state->sbox);
        permute(block, state->pbox);
    }

    xorblocks((unsigned char*)block, state->key_schedule[TRIDENT_TROUNDS], BLOCKSIZE);
    memcpy(output, block, BLOCKSIZE);
}

void trident_dec (trident_state_curr* state, unsigned char output[BLOCKSIZE], const unsigned char input[BLOCKSIZE], bigint block_id)
{
    unsigned short block[16];
    memcpy(block, input, BLOCKSIZE);

    xorblocks((unsigned char*)block, state->key_schedule[TRIDENT_TROUNDS], BLOCKSIZE);

    for (unint r=TRIDENT_TROUNDS; r>0; r--) {
        invperm(block, state->pbox);
        substitute(block, state->sbox_inverse);
        xorblocks((unsigned char*)block, state->key_schedule[r - 1], BLOCKSIZE);
    }

    bigint* bptr = (bigint*)block;
    bptr[0] ^= block_id;

    memcpy(output, block, BLOCKSIZE);
}

void trident_cleanup (trident_state_curr* state)
{
    if (!state) return;
    memset(state, 0, sizeof(trident_state_curr));
}
