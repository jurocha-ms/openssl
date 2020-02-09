/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>

struct bio_method_st {
    int type;
    char *name;
    int (__cdecl *bwrite) (BIO *, const char *, size_t, size_t *);
    int (__cdecl *bwrite_old) (BIO *, const char *, int);
    int (__cdecl *bread) (BIO *, char *, size_t, size_t *);
    int (__cdecl *bread_old) (BIO *, char *, int);
    int (__cdecl *bputs) (BIO *, const char *);
    int (__cdecl *bgets) (BIO *, char *, int);
    long (__cdecl *ctrl) (BIO *, int, long, void *);
    int (__cdecl *create) (BIO *);
    int (__cdecl *destroy) (BIO *);
    long (__cdecl *callback_ctrl) (BIO *, int, BIO_info_cb *);
};

void __cdecl bio_free_ex_data(BIO *bio);
void __cdecl bio_cleanup(void);


/* Old style to new style BIO_METHOD conversion functions */
int __cdecl bwrite_conv(BIO *bio, const char *data, size_t datal, size_t *written);
int __cdecl bread_conv(BIO *bio, char *data, size_t datal, size_t *read);
