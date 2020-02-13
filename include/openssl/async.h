/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>

#ifndef HEADER_ASYNC_H
# define HEADER_ASYNC_H

#if defined(_WIN32)
# if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> to use this */
#define OSSL_ASYNC_FD       HANDLE
#define OSSL_BAD_ASYNC_FD   INVALID_HANDLE_VALUE
# endif
#else
#define OSSL_ASYNC_FD       int
#define OSSL_BAD_ASYNC_FD   -1
#endif
# include <openssl/asyncerr.h>


# ifdef  __cplusplus
extern "C" {
# endif

typedef struct async_job_st ASYNC_JOB;
typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;

#define ASYNC_ERR      0
#define ASYNC_NO_JOBS  1
#define ASYNC_PAUSE    2
#define ASYNC_FINISH   3

int __cdecl ASYNC_init_thread(size_t max_size, size_t init_size);
void __cdecl ASYNC_cleanup_thread(void);

#ifdef OSSL_ASYNC_FD
ASYNC_WAIT_CTX * __cdecl ASYNC_WAIT_CTX_new(void);
void __cdecl ASYNC_WAIT_CTX_free(ASYNC_WAIT_CTX *ctx);
int __cdecl ASYNC_WAIT_CTX_set_wait_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                               OSSL_ASYNC_FD fd,
                               void *custom_data,
                               void (__cdecl *cleanup)(ASYNC_WAIT_CTX *, const void *,
                                               OSSL_ASYNC_FD, void *));
int __cdecl ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                        OSSL_ASYNC_FD *fd, void **custom_data);
int __cdecl ASYNC_WAIT_CTX_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd,
                               size_t *numfds);
int __cdecl ASYNC_WAIT_CTX_get_changed_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *addfd,
                                   size_t *numaddfds, OSSL_ASYNC_FD *delfd,
                                   size_t *numdelfds);
int __cdecl ASYNC_WAIT_CTX_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key);
#endif

int __cdecl ASYNC_is_capable(void);

int __cdecl ASYNC_start_job(ASYNC_JOB **job, ASYNC_WAIT_CTX *ctx, int *ret,
                    int (__cdecl *func)(void *), void *args, size_t size);
int __cdecl ASYNC_pause_job(void);

ASYNC_JOB * __cdecl ASYNC_get_current_job(void);
ASYNC_WAIT_CTX * __cdecl ASYNC_get_wait_ctx(ASYNC_JOB *job);
void __cdecl ASYNC_block_pause(void);
void __cdecl ASYNC_unblock_pause(void);


# ifdef  __cplusplus
}
# endif
#endif
