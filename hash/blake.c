#include "hash_interface.h"
#include <openssl/evp.h>
#include <string.h>
typedef const unsigned char cuchar;
typedef unsigned char uchar;
void tridentblake (
    uchar output[64], 
    cuchar input[64],
    cuchar* input2, 
    cuchar key[BLAKESIZE]
)
{
    uchar zero_block[64] = { 0 };
    EVP_MD_CTX* ctx = NULL;
    int ok = 0;

    do {
        ctx = EVP_MD_CTX_new();
        if (!ctx) break;

        if (EVP_DigestInit_ex(ctx, EVP_blake2b512(), NULL) != 1) break;

        if (key) {
            if (EVP_DigestUpdate(ctx, key, BLAKESIZE) != 1) break;
        }

        if (EVP_DigestUpdate(ctx, input, 64) != 1) break;

        if (input2) {
            if (EVP_DigestUpdate(ctx, input2, 64) != 1) break;
        } else {
            if (EVP_DigestUpdate(ctx, zero_block, sizeof(zero_block)) != 1) break;
        }

        if (EVP_DigestFinal_ex(ctx, output, NULL) != 1) break;
        ok = 1;
    } while (0);

    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }

    if (!ok) {
        memset(output, 0, 64);
    }
}

