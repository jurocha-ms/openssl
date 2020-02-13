/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RAND_H
# define HEADER_RAND_H

# include <stdlib.h>
# include <openssl/ossl_typ.h>
# include <openssl/e_os2.h>
# include <openssl/randerr.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct rand_meth_st {
    int (__cdecl *seed) (const void *buf, int num);
    int (__cdecl *bytes) (unsigned char *buf, int num);
    void (__cdecl *cleanup) (void);
    int (__cdecl *add) (const void *buf, int num, double randomness);
    int (__cdecl *pseudorand) (unsigned char *buf, int num);
    int (__cdecl *status) (void);
};

int __cdecl RAND_set_rand_method(const RAND_METHOD *meth);
const RAND_METHOD * __cdecl RAND_get_rand_method(void);
# ifndef OPENSSL_NO_ENGINE
int __cdecl RAND_set_rand_engine(ENGINE *engine);
# endif

RAND_METHOD * __cdecl RAND_OpenSSL(void);

# if OPENSSL_API_COMPAT < 0x10100000L
#   define RAND_cleanup() while(0) continue
# endif
int __cdecl RAND_bytes(unsigned char *buf, int num);
int __cdecl RAND_priv_bytes(unsigned char *buf, int num);
DEPRECATEDIN_1_1_0(int RAND_pseudo_bytes(unsigned char *buf, int num))

void __cdecl RAND_seed(const void *buf, int num);
void __cdecl RAND_keep_random_devices_open(int keep);

# if defined(__ANDROID__) && defined(__NDK_FPABI__)
__NDK_FPABI__	/* __attribute__((pcs("aapcs"))) on ARM */
# endif
void __cdecl RAND_add(const void *buf, int num, double randomness);
int __cdecl RAND_load_file(const char *file, long max_bytes);
int __cdecl RAND_write_file(const char *file);
const char * __cdecl RAND_file_name(char *file, size_t num);
int __cdecl RAND_status(void);

# ifndef OPENSSL_NO_EGD
int __cdecl RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes);
int __cdecl RAND_egd(const char *path);
int __cdecl RAND_egd_bytes(const char *path, int bytes);
# endif

int __cdecl RAND_poll(void);

# if defined(_WIN32) && (defined(BASETYPES) || defined(_WINDEF_H))
/* application has to include <windows.h> in order to use these */
DEPRECATEDIN_1_1_0(void RAND_screen(void))
DEPRECATEDIN_1_1_0(int RAND_event(UINT, WPARAM, LPARAM))
# endif


#ifdef  __cplusplus
}
#endif

#endif
