/* 
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
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
 * ccCast.h - shim between openssl-based CAST and CommonEncryption.
 *
 * Created 3/30/06 by Doug Mitchell. 
 */

#ifndef	_CC_CCCAST_H_
#define _CC_CCCAST_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccmode.h>

#include <CommonCrypto/CommonCryptoPriv.h>
#include <CommonCrypto/cast.h>

#include <sys/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

int cast_cc_set_key(
	CAST_KEY *cx, 
	const void *rawKey, 
	size_t keyLength,
	int forEncrypt);

void cast_cc_encrypt(CAST_KEY *cx, const void *blockIn, void *blockOut);
void cast_cc_decrypt(CAST_KEY *cx, const void *blockIn, void *blockOut);

const struct ccmode_cbc *cccast_cbc_encrypt_mode();
const struct ccmode_ecb *cccast_ecb_encrypt_mode();
const struct ccmode_ofb *cccast_ofb_encrypt_mode();
const struct ccmode_ctr *cccast_ctr_encrypt_mode();
const struct ccmode_cfb *cccast_cfb_encrypt_mode();
const struct ccmode_cfb8 *cccast_cfb8_encrypt_mode();

const struct ccmode_cbc *cccast_cbc_decrypt_mode();
const struct ccmode_ecb *cccast_ecb_decrypt_mode();
const struct ccmode_ofb *cccast_ofb_decrypt_mode();
const struct ccmode_ctr *cccast_ctr_decrypt_mode();
const struct ccmode_cfb *cccast_cfb_decrypt_mode();
const struct ccmode_cfb8 *cccast_cfb8_decrypt_mode();

const struct ccmode_cbc *cccast_cbc_crypt_mode();
const struct ccmode_ecb *cccast_ecb_crypt_mode();
const struct ccmode_ofb *cccast_ofb_crypt_mode();
const struct ccmode_ctr *cccast_ctr_crypt_mode();
const struct ccmode_cfb *cccast_cfb_crypt_mode();
const struct ccmode_cfb8 *cccast_cfb8_crypt_mode();

#ifdef  __cplusplus
}
#endif

#endif	/* _CC_CCCAST_H_ */
