// SPDX-License-Identifier: Apache-2.0

#ifndef _KBS
#define _KBS

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "../snp_attest.h"

/*
 * Identifiers for all possible TEE architectures.
 */
enum tee {
        TEE_SEV,
        TEE_SGX,
        TEE_SNP,
        TEE_TDX,
};

/*
 * The type of KBS operation to be performed.
 */
enum curl_post_type {
        KBS_CURL_REQ,
        KBS_CURL_ATTEST,
        KBS_CURL_GET_KEY,
};

// kbs_util.c
char *tee_str(int);
char *find_cookie(char *, char *);
int read_cookie_val(char *, char *);
int json_parse_str(char *, char *, char *);

// kbs_types.c
int kbs_request_marshal(char *, int, char *);
int kbs_challenge(CURL *, char *, char *, char *);
int kbs_attest(CURL *, char *, struct snp_report *, BIGNUM *, BIGNUM *, char *);
int kbs_get_key(CURL *, char *, char *, EVP_PKEY *, char *);

// kbs_curl.c
int kbs_curl_post(CURL *, char *, char *, char *, int);
int kbs_curl_get(CURL *, char *, char *, char *, int);

// kbs_crypto.c
int kbs_tee_pubkey_create(EVP_PKEY **, BIGNUM **, BIGNUM **);
int kbs_nonce_pubkey_hash(char *, EVP_PKEY *, unsigned char **, unsigned int *);
void BN_b64(BIGNUM *, char *);
int rsa_pkey_decrypt(EVP_PKEY *, char *, char **);

#endif /* _KBS */
