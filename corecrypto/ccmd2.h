/*
 *  ccmd2.h
 *  corecrypto
 *
 */

#ifndef _CORECRYPTO_CCMD2_H_
#define _CORECRYPTO_CCMD2_H_

#include <corecrypto/ccdigest.h>

#define CCMD2_BLOCK_SIZE   16
#define CCMD2_OUTPUT_SIZE  16
#define CCMD2_STATE_SIZE   16

extern const uint32_t ccmd2_initial_state[4];

/* Selector */
const struct ccdigest_info *ccmd2_di(void);

/* Implementations */
extern const struct ccdigest_info ccmd2_ltc_di;

#endif /* _CORECRYPTO_CCMD2_H_ */

