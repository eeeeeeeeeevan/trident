#pragma once

#include <limits.h>
#include <stdint.h>

typedef unsigned int uint;
typedef unsigned long long ull; 

// ALWAYS: SUCCESS = 0
// ANY NUMBER > 0 -> WTF
typedef enum {
    SUCCESS = 0,
    ERRORALLOC = 1,
    // inv param
    ERRINVPARAM = 2,
    ERRIO = 3,
    // err sanity check
    ERRSCHECKF = 4,
    INVFILEERR = 5 // inv file
} currstat;

#define MACMIN(a, b) ((a) < (b) ? (a) : (b))
#define MACMAX(a, b) ((a) > (b) ? (a) : (b))

// swapper macro
#define FSWAP(type, a, b) do { \
    type _temp = (a); \
    (a) = (b); \
    (b) = _temp; \
} while (0)
