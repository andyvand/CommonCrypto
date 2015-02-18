/*
 *  ccripemd.h
 *  corecrypto
 *
 */

#ifndef _CORECRYPTO_CCRIPEMD_H_
#define _CORECRYPTO_CCRIPEMD_H_

#include <corecrypto/ccdigest.h>

#define CCRMD128_BLOCK_SIZE 64
#define CCRMD128_OUTPUT_SIZE 16
#define CCRMD128_STATE_SIZE (CCRMD128_OUTPUT_SIZE / 4)

#define CCRMD160_BLOCK_SIZE 64
#define CCRMD160_OUTPUT_SIZE 20
#define CCRMD160_STATE_SIZE (CCRMD160_OUTPUT_SIZE / 4)

#define CCRMD256_BLOCK_SIZE 64
#define CCRMD256_OUTPUT_SIZE 32
#define CCRMD256_STATE_SIZE (CCRMD256_OUTPUT_SIZE / 4)

#define CCRMD320_BLOCK_SIZE 64
#define CCRMD320_OUTPUT_SIZE 40
#define CCRMD320_STATE_SIZE (CCRMD320_OUTPUT_SIZE / 4)

typedef struct CC_RMD128state_st {
    int num;
    unsigned char data[CCRMD128_BLOCK_SIZE];
    CC_LONG hash[CCRMD128_STATE_SIZE];
    CC_LONG Nl[CCRMD128_STATE_SIZE];
} CC_RMD128_CTX;

typedef struct CC_RMD160state_st {
    int num;
    unsigned char data[CCRMD160_BLOCK_SIZE];
    CC_LONG hash[CCRMD160_STATE_SIZE];
    CC_LONG Nl[CCRMD160_STATE_SIZE];
} CC_RMD160_CTX;

typedef struct CC_RMD256state_st {
    int num;
    unsigned char data[CCRMD256_BLOCK_SIZE];
    CC_LONG hash[CCRMD256_STATE_SIZE];
    CC_LONG Nl[CCRMD256_STATE_SIZE];
} CC_RMD256_CTX;

typedef struct CC_RMD320state_st {
    CC_LONG num;
    unsigned char data[CCRMD320_BLOCK_SIZE];
    CC_LONG hash[CCRMD320_STATE_SIZE];
    CC_LONG Nl[CCRMD320_STATE_SIZE];
} CC_RMD320_CTX;

extern const uint32_t ccrmd128_initial_state[4];
extern const uint32_t ccrmd160_initial_state[4];
extern const uint32_t ccrmd256_initial_state[4];
extern const uint32_t ccrmd320_initial_state[4];

/* Selector */
const struct ccdigest_info *ccrmd128_di(void);
const struct ccdigest_info *ccrmd160_di(void);
const struct ccdigest_info *ccrmd256_di(void);
const struct ccdigest_info *ccrmd320_di(void);

/* Implementations */
const struct ccdigest_info ccrmd128_ltc_di;
const struct ccdigest_info ccrmd160_ltc_di;
const struct ccdigest_info ccrmd256_ltc_di;
const struct ccdigest_info ccrmd320_ltc_di;

int CC_RMD128_Init(CC_RMD128_CTX *c);
int CC_RMD128_Update(CC_RMD128_CTX *c, const void *data, CC_LONG len);
int CC_RMD128_Final(unsigned char *md, CC_RMD128_CTX *c);

int CC_RMD160_Init(CC_RMD160_CTX *c);
int CC_RMD160_Update(CC_RMD160_CTX *c, const void *data, CC_LONG len);
int CC_RMD160_Final(unsigned char *md, CC_RMD160_CTX *c);

int CC_RMD256_Init(CC_RMD256_CTX *c);
int CC_RMD256_Update(CC_RMD256_CTX *c, const void *data, CC_LONG len);
int CC_RMD256_Final(unsigned char *md, CC_RMD256_CTX *c);

int CC_RMD320_Init(CC_RMD320_CTX *c);
int CC_RMD320_Update(CC_RMD320_CTX *c, const void *data, CC_LONG len);
int CC_RMD320_Final(unsigned char *md, CC_RMD320_CTX *c);

#endif /* _CORECRYPTO_CCRIPEMD_H_ */
