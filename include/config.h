#pragma once
#include "types.h"

#define ROUNDC 24
#define BLOCKSIZE 32
#define MKEYSIZE 128
#define FULLIVSIZE 128
#define SBOXSIZE 65536

#define HASHOUTSIZE 64
#define trident_HASH_COUNT 4

#define KSBLOCKS (ROUNDC + 1)

#define BLAKESIZE 128
#define SHA512SIZE 64
#define SHAEXTSIZE 640
#define SHA3SIZE 72
#define SHA3EXTSIZE 192
#define WPKEYSIZE 80

#define TOTALKSIZE (MKEYSIZE +   \
                    BLAKESIZE +   \
                    SHA512SIZE +  \
                    SHAEXTSIZE +  \
                    SHA3SIZE +    \
                   SHA3EXTSIZE + \
                    WPKEYSIZE)

#define MINMEM 20
#define MAXMEM 64
#define MINCPUBIAS 0.1
#define MAXCPUBIAS 1000.0

#define GCHUNKSIZE (8 * 1024 * 1024)

