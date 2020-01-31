/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CMAC_H
# define HEADER_CMAC_H

# ifndef OPENSSL_NO_CMAC

#ifdef __cplusplus
extern "C" {
#endif

# include <openssl/evp.h>

/* Opaque */
typedef struct CMAC_CTX_st CMAC_CTX;

CMAC_CTX * __cdecl CMAC_CTX_new(void);
void __cdecl CMAC_CTX_cleanup(CMAC_CTX *ctx);
void __cdecl CMAC_CTX_free(CMAC_CTX *ctx);
EVP_CIPHER_CTX * __cdecl CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx);
int __cdecl CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in);

int __cdecl CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen,
              const EVP_CIPHER *cipher, ENGINE *impl);
int __cdecl CMAC_Update(CMAC_CTX *ctx, const void *data, size_t dlen);
int __cdecl CMAC_Final(CMAC_CTX *ctx, unsigned char *out, size_t *poutlen);
int __cdecl CMAC_resume(CMAC_CTX *ctx);

#ifdef  __cplusplus
}
#endif

# endif
#endif
