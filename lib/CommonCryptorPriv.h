/* 
 * Copyright (c) 2006-2010 Apple, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

/* 
 * CommonCryptorPriv.h - interface between CommonCryptor and operation- and
 *           algorithm-specific service providers. 
 */

#ifndef _CC_COMMON_CRYPTOR_PRIV_
#define _CC_COMMON_CRYPTOR_PRIV_

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonCryptorSPI.h>

#include <dispatch/dispatch.h>

#include <CommonCrypto/corecryptoSymmetricBridge.h>

#ifdef DEBUG
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
    
    /* Byte-Size Constants */
#define CCMAXBUFFERSIZE 128             /* RC2/RC5 Max blocksize */
#define DEFAULT_CRYPTOR_MALLOC 4096
#define CC_STREAMKEYSCHED  2048
#define CC_MODEKEYSCHED  2048
#define CC_MAXBLOCKSIZE  128

#ifndef CIPHERMODE_T_DEFINED
#define CIPHERMODE_T_DEFINED 1
typedef struct cipherMode_t {
    dispatch_once_t init;
    const struct ccmode_ecb* ecb;
    const struct ccmode_cbc* cbc;
    const struct ccmode_cfb* cfb;
    const struct ccmode_cfb8* cfb8;
    const struct ccmode_ctr* ctr;
    const struct ccmode_ofb* ofb;
    const struct ccmode_xts* xts;
    const struct ccmode_gcm* gcm;
    const struct ccmode_ccm* ccm;
} cipherMode;
#endif /* CIPHERMODE_T_DEFINED */

#ifndef CC_SUPPORTED_CIPHERS
#define CC_SUPPORTED_CIPHERS 7
#endif /* CC_SUPPORTED_CIPHERS */
    
#ifndef CC_DIRECTIONS
#define CC_DIRECTIONS 2
#endif /* CC_DIRECTIONS */
    
#ifndef CORECRYPTOMODE_DEFINED
#define CORECRYPTOMODE_DEFINED 1
    
    typedef union {
        const struct ccmode_ecb *ecb;
        const struct ccmode_cbc *cbc;
        const struct ccmode_cfb *cfb;
        const struct ccmode_cfb8 *cfb8;
        const struct ccmode_ctr *ctr;
        const struct ccmode_ofb *ofb;
        const struct ccmode_xts *xts;
        const struct ccmode_gcm *gcm;
        const struct ccmode_ccm *ccm;
    } corecryptoMode;
#endif /* CORECRYPTOMODE_DEFINED */

#ifndef CBCWITHIV_DEFINED
#define CBCWITHIV_DEFINED 1
    
    typedef struct cbc_with_iv_t {
        uint8_t iv[16];
        cccbc_ctx cbc;
    } cbc_iv_ctx;
#endif /* CBCWITHIV_DEFINED */
    
#ifndef CCMNONCE_DEFINED
#define CCMNONCE_DEFINED 1
    
    typedef struct ccm_with_nonce_t {
        size_t total_len;
        size_t mac_size;
        size_t nonce_size;
        size_t ad_len;
        uint8_t nonce_buf[16];
        uint8_t mac[16];
        struct _ccmode_ccm_nonce nonce;
        ccccm_ctx ccm;
    } ccm_nonce_ctx;
#endif /* CCMNONCE_DEFINED */

#ifndef MODECTX_DEFINED
#define MODECTX_DEFINED 1
    
    typedef union {
        void *data;
        ccecb_ctx *ecb;
        cbc_iv_ctx *cbc;
        cccfb_ctx *cfb;
        cccfb8_ctx *cfb8;
        ccctr_ctx *ctr;
        ccofb_ctx *ofb;
        ccxts_ctx *xts;
        ccgcm_ctx *gcm;
        ccm_nonce_ctx *ccm;
    } modeCtx;
#endif /* MODECTX_DEFINED */

    /** Setup the mode
     @param cipher		The index of the LTC Cipher - must be registered
     @param IV		The initial vector
     @param key		The input symmetric key
     @param keylen		The length of the input key (octets)
     @param tweak		The input tweak or salt
     @param tweaklen	The length of the tweak or salt (if variable)
     (octets)
     @param options		Mask for any mode options
     @param ctx		[out] The destination of the mode context
     */
    
    typedef void (*ccmode_setup_p)(const corecryptoMode modeObj, const void *iv,
    const void *key, size_t keylen, const void *tweak,
    size_t tweaklen, int options, modeCtx ctx);
    /** Encrypt a block
     @param pt		The plaintext
     @param ct		[out] The ciphertext
     @param len		the length of data (in == out) octets
     @param ctx		The mode context
     @return # bytes encrypted
     */
    
    typedef void (*ccmode_encrypt_p)(const corecryptoMode modeObj, const void *pt, void *ct, size_t len, modeCtx ctx);
    
    /** Decrypt a block
     @param ct		The ciphertext
     @param pt		[out] The plaintext
     @param len		the length of data (in == out) octets
     @param ctx		The mode context
     @return # bytes encrypted
     */
    typedef void (*ccmode_decrypt_p)(const corecryptoMode modeObj, const void *ct, void *pt, size_t len, modeCtx ctx);
    
    /** Encrypt a block with a tweak (XTS mode currently)
     @param pt		The plaintext
     @param ct		[out] The ciphertext
     @param len		the length of data (in == out) octets
     @param tweak		The 128--bit encryption tweak (e.g. sector
     number)
     @param ctx		The mode context
     @return # bytes encrypted
     */
    typedef void (*ccmode_encrypt_tweaked_p)(const corecryptoMode modeObj, const void *pt, size_t len,
    void *ct, const void *tweak, modeCtx ctx);
    /** Decrypt a block with a tweak (XTS mode currently)
     @param ct		The ciphertext
     @param pt		[out] The plaintext
     @param len		the length of data (in == out) octets
     @param ctx		The mode context
     @return # bytes encrypted
     */
    typedef void (*ccmode_decrypt_tweaked_p)(const corecryptoMode modeObj, const void *ct, size_t len,
    void *pt, const void *tweak, modeCtx ctx);
    /** Terminate the mode
     @param ctx		[out] The mode context
     */
    typedef int (*ccmode_done_p)(const corecryptoMode modeObj, modeCtx ctx);
    /** Set an Initial Vector
     @param IV		The initial vector
     @param len		The length of the initial vector
     @param ctx		The mode context
     */
    typedef int (*ccmode_setiv_p)(const corecryptoMode modeObj, const void *iv, uint32_t len, modeCtx ctx);
    /** Get an Initial Vector
     @param IV		[out] The initial vector
     @param len		The length of the initial vector
     @param ctx		The mode context
     */
    typedef int (*ccmode_getiv_p)(const corecryptoMode modeObj, void *iv, uint32_t *len, modeCtx ctx);
    
    /** Get the mode context size
     @param modeObj a pointer to the mode object.
     @return the size of the context
     */
    typedef size_t (*ccmode_get_ctx_size)(const corecryptoMode modeObj);
    
    /** Get the mode block size
     @param modeObj a pointer to the mode object.
     @return the size of the block
     */
    typedef size_t (*ccmode_get_block_size)(const corecryptoMode modeObj);

#ifndef CC2CMODEDESCRIPTOR_DEFINED
#define CC2CMODEDESCRIPTOR_DEFINED 1
    
    typedef struct cc2CCModeDescriptor_t {
        //    ccBufStrat              bufStrat;
        ccmode_get_ctx_size     mode_get_ctx_size;
        ccmode_get_block_size   mode_get_block_size;
        ccmode_setup_p          mode_setup;
        ccmode_encrypt_p        mode_encrypt;
        ccmode_decrypt_p        mode_decrypt;
        ccmode_encrypt_tweaked_p mode_encrypt_tweaked;
        ccmode_decrypt_tweaked_p mode_decrypt_tweaked;
        ccmode_done_p           mode_done;
        ccmode_setiv_p          mode_setiv;
        ccmode_getiv_p          mode_getiv;
    } cc2CCModeDescriptor, *cc2CCModeDescriptorPtr;
#endif /* CC2CMODEDESCRIPTOR_DEFINED */

#define ACTIVE 1
#define RELEASED 0xDEADBEEF

    typedef int (*cc_encrypt_pad_p)(modeCtx ctx, const cc2CCModeDescriptor *modeptr, const corecryptoMode modeObj, void *buff, size_t startpoint, void *cipherText, size_t *moved);
    typedef int (*cc_decrypt_pad_p)(modeCtx ctx, const cc2CCModeDescriptor *modeptr, const corecryptoMode modeObj, void *buff, size_t startpoint, void *plainText, size_t *moved);

    /*
     * Maximum space needed for padding.
     */
    
    typedef size_t (*ccpadlen_p) (int encrypt, const cc2CCModeDescriptor *modeptr, const corecryptoMode modeObj, size_t inputLength, bool final);
    
    /*
     * How many bytes to reserve to enable padding - this is pre-encrypt/decrypt bytes.
     */
    
    typedef size_t (*ccreserve_p) (int encrypt, const cc2CCModeDescriptor *modeptr, const corecryptoMode modeObj);

#ifndef CC2CCPADDINGDESCRIPTOR_DEFINED
#define CC2CCPADDINGDESCRIPTOR_DEFINED 1
    
    typedef struct cc2CCPaddingDescriptor_t {
        cc_encrypt_pad_p    encrypt_pad;
        cc_decrypt_pad_p    decrypt_pad;
        ccpadlen_p          padlen;
        ccreserve_p         padreserve;
    } cc2CCPaddingDescriptor, *cc2CCPaddingDescriptorPtr;
#endif /* CC2CCPADDINGDESCRIPTOR_DEFINED */

    extern const cc2CCModeDescriptor ccecb_mode;
    extern const cc2CCModeDescriptor cccbc_mode;
    extern const cc2CCModeDescriptor cccfb_mode;
    extern const cc2CCModeDescriptor cccfb8_mode;
    extern const cc2CCModeDescriptor ccctr_mode;
    extern const cc2CCModeDescriptor ccofb_mode;
    extern const cc2CCModeDescriptor ccxts_mode;
    extern const cc2CCModeDescriptor ccgcm_mode;
    extern const cc2CCModeDescriptor ccccm_mode;

typedef struct _CCCryptor {
    struct _CCCryptor *compat;
#ifdef DEBUG
    uint64_t        active;
    uint64_t        cryptorID;
#endif
    uint8_t         buffptr[32];
    size_t          bufferPos;
    size_t          bytesProcessed;
    size_t          cipherBlocksize;

    CCAlgorithm     cipher;
    CCMode          mode;
    CCOperation     op;        /* kCCEncrypt, kCCDecrypt, or kCCBoth */
    
    corecryptoMode  symMode[CC_DIRECTIONS];
    const cc2CCModeDescriptor *modeDesc;
    modeCtx         ctx[CC_DIRECTIONS];
    const cc2CCPaddingDescriptor *padptr;
    
} CCCryptor;
    
static inline CCCryptor *
getRealCryptor(CCCryptorRef p, int checkactive) {
    if(!p) return NULL;
    if(p->compat) p = p->compat;
#ifdef DEBUG
    if(checkactive && p->active != ACTIVE) printf("Using Finalized Cryptor %16llx\n", p->cryptorID);
#endif
    return p;
}

#define CCCRYPTOR_SIZE  sizeof(struct _CCCryptor)
#define kCCContextSizeGENERIC (sizeof(struct _CCCryptor))
#define CC_COMPAT_SIZE (sizeof(void *)*2)


const corecryptoMode getCipherMode(CCAlgorithm cipher, CCMode mode, CCOperation direction);

#ifdef __cplusplus
}
#endif

#endif  /* _CC_COMMON_CRYPTOR_PRIV_ */
