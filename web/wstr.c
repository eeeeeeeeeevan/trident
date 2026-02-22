#include "trident.h"
#include <stdlib.h>
#include <string.h>
#include <emscripten.h>
typedef unsigned char byte;

EMSCRIPTEN_KEEPALIVE
int trident_keygen (byte* out) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    if (fread(out, 1, MKEYSIZE, f) != MKEYSIZE) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

// [IV][memwork][ct]
EMSCRIPTEN_KEEPALIVE
int trident_encrypt (const byte* key, const byte* plaintext, int pt_len, byte* out, int memwork)
{
    byte iv[MKEYSIZE];
    hashes_t hash_keys;
    memset(&hash_keys, 0xAA, sizeof(hashes_t));

    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    if (fread(iv, 1, MKEYSIZE, f) != MKEYSIZE) {
        fclose(f);
        return -1;
    }
    fclose(f);

    if (memwork < MINMEM) memwork = MINMEM;
    if (memwork > 26) memwork = 26;

    // heap it instead
    trident_state_curr* state = malloc(sizeof(trident_state_curr));
    if (!state) return -1;

    currstat status = trident_init(state, iv, key, &hash_keys, 1.0, memwork);
    if (status != SUCCESS) {
        free(state);
        return -(int)status;
    }

    memcpy(out, iv, MKEYSIZE);
    out[MKEYSIZE] = (byte)memwork;
    int pos = MKEYSIZE + 1;

    byte inbuf[BLOCKSIZE];
    byte outbuf[BLOCKSIZE];
    __uint128_t block_id = 0;
    int offset = 0;

    while (offset < pt_len) {
        int chunk = pt_len - offset;
        if (chunk > BLOCKSIZE) chunk = BLOCKSIZE;
        memcpy(inbuf, plaintext + offset, chunk);
        if (chunk < BLOCKSIZE) memset(inbuf + chunk, 0, BLOCKSIZE - chunk);

        trident_enc(state, outbuf, inbuf, block_id++);
        memcpy(out + pos, outbuf, BLOCKSIZE);
        pos += BLOCKSIZE;
        offset += chunk;
    }

    trident_cleanup(state);
    free(state);
    return pos;
}

EMSCRIPTEN_KEEPALIVE
int trident_decrypt (const byte* key, const byte* input, int in_len, byte* out) 
{
    if (in_len < MKEYSIZE + 1 + BLOCKSIZE) return -1;

    byte iv[MKEYSIZE];
    hashes_t hash_keys;
    memset(&hash_keys, 0xAA, sizeof(hashes_t));

    memcpy(iv, input, MKEYSIZE);
    unsigned int memwork = input[MKEYSIZE];

    trident_state_curr* state = malloc(sizeof(trident_state_curr));
    if (!state) return -1;

    currstat status = trident_init(state, iv, key, &hash_keys, 1.0, memwork);
    if (status != SUCCESS) {
        free(state);
        return -(int)status;
    }

    int data_start = MKEYSIZE + 1;
    int data_len = in_len - data_start;
    int num_blocks = data_len / BLOCKSIZE;

    byte inbuf[BLOCKSIZE];
    byte outbuf[BLOCKSIZE];
    __uint128_t block_id = 0;
    int pos = 0;

    for (int i = 0; i < num_blocks; i++) {
        memcpy(inbuf, input + data_start + i * BLOCKSIZE, BLOCKSIZE);
        trident_dec(state, outbuf, inbuf, block_id++);
        memcpy(out + pos, outbuf, BLOCKSIZE);
        pos += BLOCKSIZE;
    }

    trident_cleanup(state);
    free(state);
    return pos;
}

EMSCRIPTEN_KEEPALIVE
void* wasm_malloc(int size) {
    return malloc(size);
}

EMSCRIPTEN_KEEPALIVE
void wasm_free(void* ptr) {
    free(ptr);
}

EMSCRIPTEN_KEEPALIVE
int get_mkeysize(void) {
    return MKEYSIZE;
}

EMSCRIPTEN_KEEPALIVE
int get_blocksize(void) {
    return BLOCKSIZE;
}
