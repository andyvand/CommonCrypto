#ifndef __CCDH_H__
#define __CCDH_H__

#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng.h>

struct ccdh_const_gp_t {
	cc_size n;
	cc_size l;
	cc_unit *data;
	cc_unit *g;
};

typedef struct ccdh_const_gp_t *ccdh_const_gp_t;

#define ccdh_ccn_size(dh) (ccn_sizeof_size(sizeof(void *)) + ccn_sizeof_size(dh->n) + ccn_sizeof_size(8192*4))

struct ccdh_gp_t {
	ccdh_const_gp_t gp;
	cczp_t zp;
};
typedef struct ccdh_gp_t ccdh_gp_t;

typedef struct ccdh_gp_t ccdh_ctx_header_t;

typedef struct ccdh_full_ctx ccdh_full_ctx_t;

struct ccdh_full_ctx {
	ccdh_ctx_header_t *hdr;
	void *_full;
	void *pub;
};

extern ccdh_const_gp_t ccdh_gp_rfc5114_MODP_2048_256(void);

#define CCDH_GP_N(q) (q).gp->n
#define CCDH_GP_L(q) (q).gp->l
#define CCDH_GP_G(q) (q).gp->g
#define CCDH_GP_RECIP(q) (q).gp->data
#define CCDH_GP_PRIME(q) ((q).gp->data + CCDH_GP_N(q))

extern cc_size ccdh_gp_n(ccdh_gp_t gp);
extern cc_unit *ccdh_gp_g(ccdh_gp_t gp);
extern size_t ccdh_gp_prime_size(ccdh_const_gp_t gp);
extern cc_unit *ccdh_gp_recip(ccdh_gp_t gp);
extern cc_unit *ccdh_gp_prime(ccdh_gp_t gp);

extern void ccdh_pub_ctx_decl_gp(ccdh_gp_t gp, ccdh_full_ctx_t pub);

extern int ccdh_import_pub(ccdh_gp_t gp, size_t pub_key_len, const uint8_t *pub_key, ccdh_full_ctx_t pub);

extern int ccdh_generate_key(ccdh_gp_t gp, struct ccrng_state *dhrng, ccdh_full_ctx_t priv);

extern const cc_unit * ccdh_ctx_y(ccdh_full_ctx_t priv);

extern int ccdh_compute_key(ccdh_full_ctx_t priv, ccdh_full_ctx_t pub, cc_unit *r);

#define ccdh_ctx_init(g,ctx) ctx.hdr->gp = g

#define ccdh_export_pub_size(ctx) ctx.hdr->gp->l
#define ccdh_ctx_n(ctx) ctx.hdr->gp->n

#define ccdh_pub_ctx_decl_gp(gp, p) p.pub = *(void **)&(gp->data)

#define ccdh_init_gp(t,nv,pv,gv,lv) \
    (((t->n = nv) != 0) && ((t->data = pv) != NULL) && ((t->g = gv) != NULL) && ((t->l = lv) != 0))

#define ccdh_export_pub(target,output) target.pub = output
#define ccdh_export_full(target,output) target.full = output

#define ccdh_full_ctx_decl(_size_, _name_) cc_ctx_decl(struct ccdh_full_ctx_t *, _size_, _name_)
#define ccdh_pub_ctx_decl (_size_, _name_) cc_ctx_decl(struct ccdh_full_ctx_t *,  _size_, _name_)

#define ccdh_gp_size(dh) (ccn_sizeof_size(sizeof(dh)) + (ccn_sizeof_size(sizeof(cc_unit *)) * 2) + (ccn_sizeof_size(sizeof(cc_size)) * 2) + ccn_sizeof_size(8192*4))

#define ccdh_full_ctx_size(dh) (ccn_sizeof_size(sizeof(dh)) + (ccn_sizeof_size(sizeof(cc_unit *)) * 2) + (ccn_sizeof_size(sizeof(cc_size)) * 2) + ccn_sizeof_size(8192*4))

#endif
