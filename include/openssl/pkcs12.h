/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PKCS12_H
# define HEADER_PKCS12_H

# include <openssl/bio.h>
# include <openssl/x509.h>
# include <openssl/pkcs12err.h>

#ifdef __cplusplus
extern "C" {
#endif

# define PKCS12_KEY_ID   1
# define PKCS12_IV_ID    2
# define PKCS12_MAC_ID   3

/* Default iteration count */
# ifndef PKCS12_DEFAULT_ITER
#  define PKCS12_DEFAULT_ITER     PKCS5_DEFAULT_ITER
# endif

# define PKCS12_MAC_KEY_LENGTH 20

# define PKCS12_SALT_LEN 8

/* It's not clear if these are actually needed... */
# define PKCS12_key_gen PKCS12_key_gen_utf8
# define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8

/* MS key usage constants */

# define KEY_EX  0x10
# define KEY_SIG 0x80

typedef struct PKCS12_MAC_DATA_st PKCS12_MAC_DATA;

typedef struct PKCS12_st PKCS12;

typedef struct PKCS12_SAFEBAG_st PKCS12_SAFEBAG;

DEFINE_STACK_OF(PKCS12_SAFEBAG)

typedef struct pkcs12_bag_st PKCS12_BAGS;

# define PKCS12_ERROR    0
# define PKCS12_OK       1

/* Compatibility macros */

#if OPENSSL_API_COMPAT < 0x10100000L

# define M_PKCS12_bag_type PKCS12_bag_type
# define M_PKCS12_cert_bag_type PKCS12_cert_bag_type
# define M_PKCS12_crl_bag_type PKCS12_cert_bag_type

# define PKCS12_certbag2x509 PKCS12_SAFEBAG_get1_cert
# define PKCS12_certbag2scrl PKCS12_SAFEBAG_get1_crl
# define PKCS12_bag_type PKCS12_SAFEBAG_get_nid
# define PKCS12_cert_bag_type PKCS12_SAFEBAG_get_bag_nid
# define PKCS12_x5092certbag PKCS12_SAFEBAG_create_cert
# define PKCS12_x509crl2certbag PKCS12_SAFEBAG_create_crl
# define PKCS12_MAKE_KEYBAG PKCS12_SAFEBAG_create0_p8inf
# define PKCS12_MAKE_SHKEYBAG PKCS12_SAFEBAG_create_pkcs8_encrypt

#endif

DEPRECATEDIN_1_1_0(ASN1_TYPE *PKCS12_get_attr(const PKCS12_SAFEBAG *bag, int attr_nid))

ASN1_TYPE * __cdecl PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, int attr_nid);
int __cdecl PKCS12_mac_present(const PKCS12 *p12);
void __cdecl PKCS12_get0_mac(const ASN1_OCTET_STRING **pmac,
                     const X509_ALGOR **pmacalg,
                     const ASN1_OCTET_STRING **psalt,
                     const ASN1_INTEGER **piter,
                     const PKCS12 *p12);

const ASN1_TYPE * __cdecl PKCS12_SAFEBAG_get0_attr(const PKCS12_SAFEBAG *bag,
                                          int attr_nid);
const ASN1_OBJECT * __cdecl PKCS12_SAFEBAG_get0_type(const PKCS12_SAFEBAG *bag);
int __cdecl PKCS12_SAFEBAG_get_nid(const PKCS12_SAFEBAG *bag);
int __cdecl PKCS12_SAFEBAG_get_bag_nid(const PKCS12_SAFEBAG *bag);

X509 * __cdecl PKCS12_SAFEBAG_get1_cert(const PKCS12_SAFEBAG *bag);
X509_CRL * __cdecl PKCS12_SAFEBAG_get1_crl(const PKCS12_SAFEBAG *bag);
const STACK_OF(PKCS12_SAFEBAG) * __cdecl 
PKCS12_SAFEBAG_get0_safes(const PKCS12_SAFEBAG *bag);
const PKCS8_PRIV_KEY_INFO * __cdecl PKCS12_SAFEBAG_get0_p8inf(const PKCS12_SAFEBAG *bag);
const X509_SIG * __cdecl PKCS12_SAFEBAG_get0_pkcs8(const PKCS12_SAFEBAG *bag);

PKCS12_SAFEBAG * __cdecl PKCS12_SAFEBAG_create_cert(X509 *x509);
PKCS12_SAFEBAG * __cdecl PKCS12_SAFEBAG_create_crl(X509_CRL *crl);
PKCS12_SAFEBAG * __cdecl PKCS12_SAFEBAG_create0_p8inf(PKCS8_PRIV_KEY_INFO *p8);
PKCS12_SAFEBAG * __cdecl PKCS12_SAFEBAG_create0_pkcs8(X509_SIG *p8);
PKCS12_SAFEBAG * __cdecl PKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid,
                                                    const char *pass,
                                                    int passlen,
                                                    unsigned char *salt,
                                                    int saltlen, int iter,
                                                    PKCS8_PRIV_KEY_INFO *p8inf);

PKCS12_SAFEBAG * __cdecl PKCS12_item_pack_safebag(void *obj, const ASN1_ITEM *it,
                                         int nid1, int nid2);
PKCS8_PRIV_KEY_INFO * __cdecl PKCS8_decrypt(const X509_SIG *p8, const char *pass,
                                   int passlen);
PKCS8_PRIV_KEY_INFO * __cdecl PKCS12_decrypt_skey(const PKCS12_SAFEBAG *bag,
                                         const char *pass, int passlen);
X509_SIG * __cdecl PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher,
                        const char *pass, int passlen, unsigned char *salt,
                        int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8);
X509_SIG * __cdecl PKCS8_set0_pbe(const char *pass, int passlen,
                        PKCS8_PRIV_KEY_INFO *p8inf, X509_ALGOR *pbe);
PKCS7 * __cdecl PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
STACK_OF(PKCS12_SAFEBAG) * __cdecl PKCS12_unpack_p7data(PKCS7 *p7);
PKCS7 * __cdecl PKCS12_pack_p7encdata(int pbe_nid, const char *pass, int passlen,
                             unsigned char *salt, int saltlen, int iter,
                             STACK_OF(PKCS12_SAFEBAG) *bags);
STACK_OF(PKCS12_SAFEBAG) * __cdecl PKCS12_unpack_p7encdata(PKCS7 *p7, const char *pass,
                                                  int passlen);

int __cdecl PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes);
STACK_OF(PKCS7) * __cdecl PKCS12_unpack_authsafes(const PKCS12 *p12);

int __cdecl PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name,
                          int namelen);
int __cdecl PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag, const char *name,
                                int namelen);
int __cdecl PKCS12_add_friendlyname_utf8(PKCS12_SAFEBAG *bag, const char *name,
                                 int namelen);
int __cdecl PKCS12_add_CSPName_asc(PKCS12_SAFEBAG *bag, const char *name,
                           int namelen);
int __cdecl PKCS12_add_friendlyname_uni(PKCS12_SAFEBAG *bag,
                                const unsigned char *name, int namelen);
int __cdecl PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage);
ASN1_TYPE * __cdecl PKCS12_get_attr_gen(const STACK_OF(X509_ATTRIBUTE) *attrs,
                               int attr_nid);
char * __cdecl PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag);
const STACK_OF(X509_ATTRIBUTE) * __cdecl 
PKCS12_SAFEBAG_get0_attrs(const PKCS12_SAFEBAG *bag);
unsigned char * __cdecl PKCS12_pbe_crypt(const X509_ALGOR *algor,
                                const char *pass, int passlen,
                                const unsigned char *in, int inlen,
                                unsigned char **data, int *datalen,
                                int en_de);
void * __cdecl PKCS12_item_decrypt_d2i(const X509_ALGOR *algor, const ASN1_ITEM *it,
                              const char *pass, int passlen,
                              const ASN1_OCTET_STRING *oct, int zbuf);
ASN1_OCTET_STRING * __cdecl PKCS12_item_i2d_encrypt(X509_ALGOR *algor,
                                           const ASN1_ITEM *it,
                                           const char *pass, int passlen,
                                           void *obj, int zbuf);
PKCS12 * __cdecl PKCS12_init(int mode);
int __cdecl PKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVP_MD *md_type);
int __cdecl PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVP_MD *md_type);
int __cdecl PKCS12_key_gen_utf8(const char *pass, int passlen, unsigned char *salt,
                        int saltlen, int id, int iter, int n,
                        unsigned char *out, const EVP_MD *md_type);
int __cdecl PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                        ASN1_TYPE *param, const EVP_CIPHER *cipher,
                        const EVP_MD *md_type, int en_de);
int __cdecl PKCS12_gen_mac(PKCS12 *p12, const char *pass, int passlen,
                   unsigned char *mac, unsigned int *maclen);
int __cdecl PKCS12_verify_mac(PKCS12 *p12, const char *pass, int passlen);
int __cdecl PKCS12_set_mac(PKCS12 *p12, const char *pass, int passlen,
                   unsigned char *salt, int saltlen, int iter,
                   const EVP_MD *md_type);
int __cdecl PKCS12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt,
                     int saltlen, const EVP_MD *md_type);
unsigned char * __cdecl OPENSSL_asc2uni(const char *asc, int asclen,
                               unsigned char **uni, int *unilen);
char * __cdecl OPENSSL_uni2asc(const unsigned char *uni, int unilen);
unsigned char * __cdecl OPENSSL_utf82uni(const char *asc, int asclen,
                                unsigned char **uni, int *unilen);
char * __cdecl OPENSSL_uni2utf8(const unsigned char *uni, int unilen);

DECLARE_ASN1_FUNCTIONS(PKCS12)
DECLARE_ASN1_FUNCTIONS(PKCS12_MAC_DATA)
DECLARE_ASN1_FUNCTIONS(PKCS12_SAFEBAG)
DECLARE_ASN1_FUNCTIONS(PKCS12_BAGS)

DECLARE_ASN1_ITEM(PKCS12_SAFEBAGS)
DECLARE_ASN1_ITEM(PKCS12_AUTHSAFES)

void __cdecl PKCS12_PBE_add(void);
int __cdecl PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
                 STACK_OF(X509) **ca);
PKCS12 * __cdecl PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey,
                      X509 *cert, STACK_OF(X509) *ca, int nid_key, int nid_cert,
                      int iter, int mac_iter, int keytype);

PKCS12_SAFEBAG * __cdecl PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert);
PKCS12_SAFEBAG * __cdecl PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags,
                               EVP_PKEY *key, int key_usage, int iter,
                               int key_nid, const char *pass);
int __cdecl PKCS12_add_safe(STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags,
                    int safe_nid, int iter, const char *pass);
PKCS12 * __cdecl PKCS12_add_safes(STACK_OF(PKCS7) *safes, int p7_nid);

int __cdecl i2d_PKCS12_bio(BIO *bp, PKCS12 *p12);
# ifndef OPENSSL_NO_STDIO
int __cdecl i2d_PKCS12_fp(FILE *fp, PKCS12 *p12);
# endif
PKCS12 * __cdecl d2i_PKCS12_bio(BIO *bp, PKCS12 **p12);
# ifndef OPENSSL_NO_STDIO
PKCS12 * __cdecl d2i_PKCS12_fp(FILE *fp, PKCS12 **p12);
# endif
int __cdecl PKCS12_newpass(PKCS12 *p12, const char *oldpass, const char *newpass);

# ifdef  __cplusplus
}
# endif
#endif
