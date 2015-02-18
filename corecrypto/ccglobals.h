/*
 * Copyright (c) 2012 Apple Inc. All Rights Reserved.
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
 *  ccGlobals.h - CommonCrypto global DATA
 */

#ifndef CCGLOBALS_H
#define CCGLOBALS_H

#include <asl.h>
#include <corecrypto/ccdh.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>

#include <CommonCrypto/CommonCryptorPriv.h>
#include <CommonCrypto/CommonRandomPriv.h>

#include "basexx.h"
#include "crc.h"
#include "CommonCRC.h"

#if __has_include(<os/alloc_once_private.h>)
#include <os/alloc_once_private.h>
#if defined(OS_ALLOC_ONCE_KEY_LIBCOMMONCRYPTO) && !defined(KERNEL)
#define _LIBCOMMONCRYPTO_HAS_ALLOC_ONCE 1
#endif
#endif

#define CN_SUPPORTED_CRCS kCN_CRC_64_ECMA_182+1
#define CN_STANDARD_BASE_ENCODERS kCNEncodingBase16+1

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#ifndef CC_SUPPORTED_CIPHERS
#define CC_SUPPORTED_CIPHERS 7
#endif /* CC_SUPPORTED_CIPHERS */

#ifndef CC_DIRECTIONS
#define CC_DIRECTIONS 2
#endif /* CC_DIRECTIONS */ 

struct cc_globals_s {
    // CommonCRC.c
    dispatch_once_t crc_init;
    crcInfo crcSelectionTab[CN_SUPPORTED_CRCS];
    
    dispatch_once_t basexx_init;
    BaseEncoderFrame encoderTab[CN_STANDARD_BASE_ENCODERS];

	// CommonDigest.c
	dispatch_once_t digest_info_init;
	const struct ccdigest_info **digest_info;
	
	// CommonRandom.c
	dispatch_once_t dev_random_init;
	dispatch_once_t drbg_init;
    
    ccInternalRandom dev_random;
    ccInternalRandom drbg;
	
	// CommonKeyDerivation.c
	mach_timebase_info_data_t timebaseInfo;
	
	// ccdebug.c
	dispatch_once_t debug_init;
	aslclient aslhandle;
	aslmsg msgptr;
    
    // CommonCryptor.c
    cipherMode cipherModeTab[CC_SUPPORTED_CIPHERS][CC_DIRECTIONS];
};
typedef struct cc_globals_s *cc_globals_t;

__attribute__((__pure__))
static inline cc_globals_t
_cc_globals(void) {
#if _LIBCOMMONCRYPTO_HAS_ALLOC_ONCE
	return (cc_globals_t) os_alloc_once(OS_ALLOC_ONCE_KEY_LIBCOMMONCRYPTO,
					       sizeof(struct cc_globals_s),
					       NULL);
#else
	static struct cc_globals_s storage;
	return &storage;
#endif
}

typedef struct ccrng_CommonCrypto_state {
    CCRNG_STATE_COMMON
    ccInternalRandom drbg;
    int fd;
} ccrng_CommonCrypto_state_t;

#endif /* CCGLOBALS_H */
