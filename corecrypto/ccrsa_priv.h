#ifndef __CCRSA_PRIV_H__
#define __CCRSA_PRIV_H__

#include <CoreFoundation/CoreFoundation.h>

#include <corecrypto/ccn.h>
#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>

extern void ccrsa_oaep_encode(const struct ccdigest_info *ccsha1_di, struct ccrng_state *rng, size_t buffer_size, cc_unit *buffer, CFIndex data_length, const UInt8 *data_ptr);

extern int ccrsa_oaep_decode(const struct ccdigest_info *ccsha1_di, size_t *text_length, UInt8 *text_buffer, size_t length, cc_unit *buffer);

typedef struct ccrsa_priv_ctx {
    cczp_t zm;
    cczp_t zp;
    cczp_t zq;
    cczp_t dp;
    cczp_t dq;
    cczp_t qinv;
} ccrsa_priv_ctx_t;

typedef struct ccrsa_pub_ctx {
    cc_size n;
    cc_unit m;
    cc_unit e;
    cc_unit d;
} ccrsa_pub_ctx_t;

typedef struct ccrsa_full_ctx
{
    ccrsa_priv_ctx_t priv;
    ccrsa_pub_ctx_t pub;
} ccrsa_full_ctx_t;

#define ccrsa_full_ctx_decl(size,target) ccrsa_full_ctx_t *target

#define ccrsa_ctx_n(ctx) ctx.n
#define ccrsa_ctx_m(ctx) *(const cc_unit *)&ctx.m
#define ccrsa_ctx_e(ctx) ctx.e
#define ccrsa_ctx_d(ctx) ctx.d
#define ccrsa_ctx_public(ctx) ctx->pub
#define ccrsa_ctx_private(ctx) ctx->priv
#define ccrsa_ctx_zm(ctx) ctx.zm
#define ccrsa_ctx_private_zp(ctx) ctx.zp
#define ccrsa_ctx_private_zq(ctx) ctx.zq
#define ccrsa_ctx_private_dp(ctx) ctx.dp
#define ccrsa_ctx_private_qinv(ctx) ctx.qinv
#define ccrsa_ctx_private_dq(ctx) ctx.dq
#define ccrsa_init_pub(t,mi,ei) t.m = mi; t.e = ei
#define ccrsa_export_pub_size(t) ccn_sizeof_size(sizeof(t))
#define ccrsa_export_priv_size(t) ccn_sizeof_size(sizeof(t))
#define ccrsa_export_pub(t,s,o) (memcpy(o,*(const void **)&t,s) <= 0)
#define ccrsa_export_priv(t,s,o) (memcpy(o,*(const void **)&t,s) <= 0)

extern void ccrsa_crt_makekey(cczp_t zm, cc_unit e, cc_unit d, cczp_t zp, cczp_t dp, cczp_t qinv, cczp_t zq, cczp_t dq);

#endif
