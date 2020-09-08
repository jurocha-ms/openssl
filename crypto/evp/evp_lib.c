/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "internal/evp_int.h"
#include "evp_locl.h"

int __cdecl EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int ret;

    if (c->cipher->set_asn1_parameters != NULL)
        ret = c->cipher->set_asn1_parameters(c, type);
    else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1) {
        switch (EVP_CIPHER_CTX_mode(c)) {
        case EVP_CIPH_WRAP_MODE:
            if (EVP_CIPHER_CTX_nid(c) == NID_id_smime_alg_CMS3DESwrap)
                ASN1_TYPE_set(type, V_ASN1_NULL, NULL);
            ret = 1;
            break;

        case EVP_CIPH_GCM_MODE:
        case EVP_CIPH_CCM_MODE:
        case EVP_CIPH_XTS_MODE:
        case EVP_CIPH_OCB_MODE:
            ret = -2;
            break;

        default:
            ret = EVP_CIPHER_set_asn1_iv(c, type);
        }
    } else
        ret = -1;
    if (ret <= 0)
        EVPerr(EVP_F_EVP_CIPHER_PARAM_TO_ASN1, ret == -2 ?
               ASN1_R_UNSUPPORTED_CIPHER :
               EVP_R_CIPHER_PARAMETER_ERROR);
    if (ret < -1)
        ret = -1;
    return ret;
}

int __cdecl EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int ret;

    if (c->cipher->get_asn1_parameters != NULL)
        ret = c->cipher->get_asn1_parameters(c, type);
    else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1) {
        switch (EVP_CIPHER_CTX_mode(c)) {

        case EVP_CIPH_WRAP_MODE:
            ret = 1;
            break;

        case EVP_CIPH_GCM_MODE:
        case EVP_CIPH_CCM_MODE:
        case EVP_CIPH_XTS_MODE:
        case EVP_CIPH_OCB_MODE:
            ret = -2;
            break;

        default:
            ret = EVP_CIPHER_get_asn1_iv(c, type);
            break;
        }
    } else
        ret = -1;
    if (ret <= 0)
        EVPerr(EVP_F_EVP_CIPHER_ASN1_TO_PARAM, ret == -2 ?
               EVP_R_UNSUPPORTED_CIPHER :
               EVP_R_CIPHER_PARAMETER_ERROR);
    if (ret < -1)
        ret = -1;
    return ret;
}

int __cdecl EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int l;

    if (type != NULL) {
        l = EVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(l <= sizeof(c->iv));
        i = ASN1_TYPE_get_octetstring(type, c->oiv, l);
        if (i != (int)l)
            return -1;
        else if (i > 0)
            memcpy(c->iv, c->oiv, l);
    }
    return i;
}

int __cdecl EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int j;

    if (type != NULL) {
        j = EVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(j <= sizeof(c->iv));
        i = ASN1_TYPE_set_octetstring(type, c->oiv, j);
    }
    return i;
}

/* Convert the various cipher NIDs and dummies to a proper OID NID */
int __cdecl EVP_CIPHER_type(const EVP_CIPHER *ctx)
{
    int nid;
    ASN1_OBJECT *otmp;
    nid = EVP_CIPHER_nid(ctx);

    switch (nid) {

    case NID_rc2_cbc:
    case NID_rc2_64_cbc:
    case NID_rc2_40_cbc:

        return NID_rc2_cbc;

    case NID_rc4:
    case NID_rc4_40:

        return NID_rc4;

    case NID_aes_128_cfb128:
    case NID_aes_128_cfb8:
    case NID_aes_128_cfb1:

        return NID_aes_128_cfb128;

    case NID_aes_192_cfb128:
    case NID_aes_192_cfb8:
    case NID_aes_192_cfb1:

        return NID_aes_192_cfb128;

    case NID_aes_256_cfb128:
    case NID_aes_256_cfb8:
    case NID_aes_256_cfb1:

        return NID_aes_256_cfb128;

    case NID_des_cfb64:
    case NID_des_cfb8:
    case NID_des_cfb1:

        return NID_des_cfb64;

    case NID_des_ede3_cfb64:
    case NID_des_ede3_cfb8:
    case NID_des_ede3_cfb1:

        return NID_des_cfb64;

    default:
        /* Check it has an OID and it is valid */
        otmp = OBJ_nid2obj(nid);
        if (OBJ_get0_data(otmp) == NULL)
            nid = NID_undef;
        ASN1_OBJECT_free(otmp);
        return nid;
    }
}

int __cdecl EVP_CIPHER_block_size(const EVP_CIPHER *e)
{
    return e->block_size;
}

int __cdecl EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->block_size;
}

int __cdecl EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *e)
{
    return e->ctx_size;
}

int EVP_Cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
               const unsigned char *in, unsigned int inl)
{
    return ctx->cipher->do_cipher(ctx, out, in, inl);
}

const EVP_CIPHER * __cdecl EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher;
}

int __cdecl EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx)
{
    return ctx->encrypt;
}

unsigned long __cdecl EVP_CIPHER_flags(const EVP_CIPHER *cipher)
{
    return cipher->flags;
}

void * __cdecl EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->app_data;
}

void __cdecl EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

void * __cdecl EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher_data;
}

void * __cdecl EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data)
{
    void *old_cipher_data;

    old_cipher_data = ctx->cipher_data;
    ctx->cipher_data = cipher_data;

    return old_cipher_data;
}

int __cdecl EVP_CIPHER_iv_length(const EVP_CIPHER *cipher)
{
    return cipher->iv_len;
}

int __cdecl EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx)
{
    int i, rv;

    if ((EVP_CIPHER_flags(ctx->cipher) & EVP_CIPH_CUSTOM_IV_LENGTH) != 0) {
        rv = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)ctx, EVP_CTRL_GET_IVLEN,
                                 0, &i);
        return (rv == 1) ? i : -1;
    }
    return ctx->cipher->iv_len;
}

const unsigned char * __cdecl EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx)
{
    return ctx->oiv;
}

const unsigned char * __cdecl EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

unsigned char * __cdecl EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

unsigned char * __cdecl EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->buf;
}

int __cdecl EVP_CIPHER_CTX_num(const EVP_CIPHER_CTX *ctx)
{
    return ctx->num;
}

void __cdecl EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num)
{
    ctx->num = num;
}

int __cdecl EVP_CIPHER_key_length(const EVP_CIPHER *cipher)
{
    return cipher->key_len;
}

int __cdecl EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->key_len;
}

int __cdecl EVP_CIPHER_nid(const EVP_CIPHER *cipher)
{
    return cipher->nid;
}

int __cdecl EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->nid;
}

int __cdecl EVP_MD_block_size(const EVP_MD *md)
{
    return md->block_size;
}

int __cdecl EVP_MD_type(const EVP_MD *md)
{
    return md->type;
}

int __cdecl EVP_MD_pkey_type(const EVP_MD *md)
{
    return md->pkey_type;
}

int __cdecl EVP_MD_size(const EVP_MD *md)
{
    if (!md) {
        EVPerr(EVP_F_EVP_MD_SIZE, EVP_R_MESSAGE_DIGEST_IS_NULL);
        return -1;
    }
    return md->md_size;
}

unsigned long __cdecl EVP_MD_flags(const EVP_MD *md)
{
    return md->flags;
}

EVP_MD * __cdecl EVP_MD_meth_new(int md_type, int pkey_type)
{
    EVP_MD *md = OPENSSL_zalloc(sizeof(*md));

    if (md != NULL) {
        md->type = md_type;
        md->pkey_type = pkey_type;
    }
    return md;
}
EVP_MD * __cdecl EVP_MD_meth_dup(const EVP_MD *md)
{
    EVP_MD *to = EVP_MD_meth_new(md->type, md->pkey_type);

    if (to != NULL)
        memcpy(to, md, sizeof(*to));
    return to;
}
void __cdecl EVP_MD_meth_free(EVP_MD *md)
{
    OPENSSL_free(md);
}
int __cdecl EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize)
{
    md->block_size = blocksize;
    return 1;
}
int __cdecl EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize)
{
    md->md_size = resultsize;
    return 1;
}
int __cdecl EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize)
{
    md->ctx_size = datasize;
    return 1;
}
int __cdecl EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags)
{
    md->flags = flags;
    return 1;
}
int __cdecl EVP_MD_meth_set_init(EVP_MD *md, int (__cdecl *init)(EVP_MD_CTX *ctx))
{
    md->init = init;
    return 1;
}
int __cdecl EVP_MD_meth_set_update(EVP_MD *md, int (__cdecl *update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count))
{
    md->update = update;
    return 1;
}
int __cdecl EVP_MD_meth_set_final(EVP_MD *md, int (__cdecl *final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md))
{
    md->final = final;
    return 1;
}
int __cdecl EVP_MD_meth_set_copy(EVP_MD *md, int (__cdecl *copy)(EVP_MD_CTX *to,
                                                 const EVP_MD_CTX *from))
{
    md->copy = copy;
    return 1;
}
int __cdecl EVP_MD_meth_set_cleanup(EVP_MD *md, int (__cdecl *cleanup)(EVP_MD_CTX *ctx))
{
    md->cleanup = cleanup;
    return 1;
}
int __cdecl EVP_MD_meth_set_ctrl(EVP_MD *md, int (__cdecl *ctrl)(EVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2))
{
    md->md_ctrl = ctrl;
    return 1;
}

int __cdecl EVP_MD_meth_get_input_blocksize(const EVP_MD *md)
{
    return md->block_size;
}
int __cdecl EVP_MD_meth_get_result_size(const EVP_MD *md)
{
    return md->md_size;
}
int __cdecl EVP_MD_meth_get_app_datasize(const EVP_MD *md)
{
    return md->ctx_size;
}
unsigned long __cdecl EVP_MD_meth_get_flags(const EVP_MD *md)
{
    return md->flags;
}
int (__cdecl * EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->init;
}
int (__cdecl * EVP_MD_meth_get_update(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                                const void *data,
                                                size_t count)
{
    return md->update;
}
int (__cdecl * EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                               unsigned char *md)
{
    return md->final;
}
int (__cdecl * EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
                                              const EVP_MD_CTX *from)
{
    return md->copy;
}
int (__cdecl * EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->cleanup;
}
int (__cdecl * EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2)
{
    return md->md_ctrl;
}

const EVP_MD * __cdecl EVP_MD_CTX_md(const EVP_MD_CTX *ctx)
{
    if (!ctx)
        return NULL;
    return ctx->digest;
}

EVP_PKEY_CTX * __cdecl EVP_MD_CTX_pkey_ctx(const EVP_MD_CTX *ctx)
{
    return ctx->pctx;
}

void __cdecl EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx)
{
    /*
     * it's reasonable to set NULL pctx (a.k.a clear the ctx->pctx), so
     * we have to deal with the cleanup job here.
     */
    if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX))
        EVP_PKEY_CTX_free(ctx->pctx);

    ctx->pctx = pctx;

    if (pctx != NULL) {
        /* make sure pctx is not freed when destroying EVP_MD_CTX */
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    } else {
        EVP_MD_CTX_clear_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    }
}

void * __cdecl EVP_MD_CTX_md_data(const EVP_MD_CTX *ctx)
{
    return ctx->md_data;
}

int (__cdecl * EVP_MD_CTX_update_fn(EVP_MD_CTX *ctx))(EVP_MD_CTX *ctx,
                                             const void *data, size_t count)
{
    return ctx->update;
}

void __cdecl EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
                              int (__cdecl *update) (EVP_MD_CTX *ctx,
                                             const void *data, size_t count))
{
    ctx->update = update;
}

void __cdecl EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void __cdecl EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int __cdecl EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}

void __cdecl EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void __cdecl EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int __cdecl EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}
