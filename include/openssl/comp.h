/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_COMP_H
# define HEADER_COMP_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_COMP
# include <openssl/crypto.h>
# include <openssl/comperr.h>
# ifdef  __cplusplus
extern "C" {
# endif



COMP_CTX * __cdecl COMP_CTX_new(COMP_METHOD *meth);
const COMP_METHOD * __cdecl COMP_CTX_get_method(const COMP_CTX *ctx);
int __cdecl COMP_CTX_get_type(const COMP_CTX* comp);
int __cdecl COMP_get_type(const COMP_METHOD *meth);
const char * __cdecl COMP_get_name(const COMP_METHOD *meth);
void __cdecl COMP_CTX_free(COMP_CTX *ctx);

int __cdecl COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen,
                        unsigned char *in, int ilen);
int __cdecl COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
                      unsigned char *in, int ilen);

COMP_METHOD * __cdecl COMP_zlib(void);

#if OPENSSL_API_COMPAT < 0x10100000L
#define COMP_zlib_cleanup() while(0) continue
#endif

# ifdef HEADER_BIO_H
#  ifdef ZLIB
const BIO_METHOD * __cdecl BIO_f_zlib(void);
#  endif
# endif


#  ifdef  __cplusplus
}
#  endif
# endif
#endif
