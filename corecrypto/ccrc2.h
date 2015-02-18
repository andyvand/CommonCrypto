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

#ifndef	_CC_RC2_H_
#define _CC_RC2_H_

#include <CommonCrypto/CommonCryptoPriv.h>
#include "rc2.h"
#include <sys/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

int rc2_cc_set_key(RC2_Schedule *cx, const void *rawKey, size_t keyLength);
void rc2_cc_encrypt(RC2_Schedule *cx, const void *blockIn, void *blockOut);
void rc2_cc_decrypt(RC2_Schedule *cx, const void *blockIn, void *blockOut);

const struct ccmode_cbc *ccrc2_cbc_encrypt_mode();
const struct ccmode_ecb *ccrc2_ecb_encrypt_mode();
const struct ccmode_ofb *ccrc2_ofb_encrypt_mode();
const struct ccmode_ctr *ccrc2_ctr_encrypt_mode();
const struct ccmode_cfb *ccrc2_cfb_encrypt_mode();
const struct ccmode_cfb8 *ccrc2_cfb8_encrypt_mode();
    
const struct ccmode_cbc *ccrc2_cbc_decrypt_mode();
const struct ccmode_ecb *ccrc2_ecb_decrypt_mode();
const struct ccmode_ofb *ccrc2_ofb_decrypt_mode();
const struct ccmode_ctr *ccrc2_ctr_decrypt_mode();
const struct ccmode_cfb *ccrc2_cfb_decrypt_mode();
const struct ccmode_cfb8 *ccrc2_cfb8_decrypt_mode();
    
const struct ccmode_cbc *ccrc2_cbc_crypt_mode();
const struct ccmode_ecb *ccrc2_ecb_crypt_mode();
const struct ccmode_ofb *ccrc2_ofb_crypt_mode();
const struct ccmode_ctr *ccrc2_ctr_crypt_mode();
const struct ccmode_cfb *ccrc2_cfb_crypt_mode();
const struct ccmode_cfb8 *ccrc2_cfb8_crypt_mode();

#ifdef  __cplusplus
}
#endif

#endif	/* _CC_RC2_H_ */