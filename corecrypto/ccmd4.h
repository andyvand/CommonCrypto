/*
 *  ccmd4.h
 *  corecrypto
 *
 */

#ifndef _CORECRYPTO_CCMD4_H_
#define _CORECRYPTO_CCMD4_H_

#include <corecrypto/ccdigest.h>

#define CCMD4_BLOCK_SIZE   64
#define CCMD4_OUTPUT_SIZE  16
#define CCMD4_STATE_SIZE   16

/* MD4 context. */
typedef struct
{
    uint32_t state[4]; /* state (ABCD) */
    uint32_t count[2]; /* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64]; /* input buffer */
} MD4_CTX;

extern const uint32_t ccmd4_initial_state[4];

/* Selector */
const struct ccdigest_info *ccmd4_di(void);

/* Implementations */
extern const struct ccdigest_info ccmd4_ltc_di;

#endif /* _CORECRYPTO_CCMD4_H_ */
