// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "kbs.h"

/*
 * Create an OpenSSL TEE public/private key pair.
 */
int
kbs_tee_pubkey_create(EVP_PKEY **pkey, BIGNUM **n, BIGNUM **e)
{
        int ret, rc;
        EVP_PKEY_CTX *ctx;

        rc = -1;
        ctx = NULL;

        /*
         * The public/private key pair will use an RSA algorithm. Generate the
         * keys' context.
         */
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (ctx == NULL) {
                printf("ERROR: creating TEE public key context\n");

                return rc;
        }

        ret = EVP_PKEY_keygen_init(ctx);
        if (ret < 1) {
                printf("ERROR: initializing TEE public key generation\n");

                goto ctx_free;
        }

        /*
         * Set key generation bits to 2048 and generate the key pair.
         */
        ret = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        if (ret < 1) {
                printf("ERROR: setting RSA keygen bits\n");

                goto ctx_free;
        }

        *pkey = NULL;
        ret = EVP_PKEY_keygen(ctx, pkey);
        if (ret < 1) {
                printf("ERROR: generating RSA key\n");

                goto ctx_free;
        }

        /*
         * Get the modulus and exponents of the key pair.
         */
        ret = EVP_PKEY_get_bn_param(*pkey, OSSL_PKEY_PARAM_RSA_N, n);
        if (ret < 0 || n == NULL) {
                printf("ERROR: getting public key modulus\n");

                goto ctx_free;
        }

        ret = EVP_PKEY_get_bn_param(*pkey, OSSL_PKEY_PARAM_RSA_E, e);
        if (ret < 0 || e == NULL) {
                printf("ERROR: getting public key exponent\n");

                goto ctx_free;
        }

        rc = 0;

ctx_free:
        EVP_PKEY_CTX_free(ctx);

        return rc;
}

/*
 * Create a SHA512 hash of the nonce and TEE public key to send to the
 * attestation server.
 */
int
kbs_nonce_pubkey_hash(char *nonce, EVP_PKEY *pkey, unsigned char **hash,
                unsigned int *size)
{
        int rc;
        EVP_MD_CTX *md_ctx;
        BIO *n_bio, *n_bio64, *e_bio, *e_bio64;
        BIGNUM *n, *e;
        char *n_b64, *e_b64;

        rc = -1;

        /*
         * Initialize an MD context and initialize the SHA512 digest.
         */
        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL) {
                printf("ERROR: generating SHA512 context\n");

                return rc;
        }

        if (EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL) < 1) {
                printf("ERROR: initializing SHA512 hash\n");

                goto md_ctx_free;
        }

        /*
         * Update the digest with the data from the nonce.
         */
        if (EVP_DigestUpdate(md_ctx, (void *) nonce, strlen(nonce)) < 1) {
                printf("ERROR: updating SHA512 digest with nonce\n");

                goto md_ctx_free;
        }

        /*
         * Update the digest with the data from the TEE public key.
         *
         * To do this, we will write the base64 encoding of the TEE public
         * key's modulus and exponent.
         */
        n = e = NULL;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) == 0) {
                printf("ERROR: unable to retrieve public key modulus\n");

                goto md_ctx_free;
        }

        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 0) {
                printf("ERROR: unable to retrieve public key exponent\n");

                goto bn_n_free;
        }

        n_b64 = (char *) malloc(1024 * sizeof(char));
        if (n_b64 == NULL)
                goto bn_e_free;

        e_b64 = (char *) malloc(1024 * sizeof(char));
        if (e_b64 == NULL) {
                free((void *) n_b64);
                goto bn_e_free;
        }

        n_bio = BIO_new(BIO_s_mem());
        e_bio = BIO_new(BIO_s_mem());

        n_bio64 = BIO_new(BIO_f_base64());
        e_bio64 = BIO_new(BIO_f_base64());

        ossl_bn_b64(n, &n_b64, n_bio, n_bio64);
        ossl_bn_b64(e, &e_b64, e_bio, e_bio64);

        if (EVP_DigestUpdate(md_ctx, (void *) n_b64, strlen(n_b64)) < 1) {
                printf("ERROR: updating SHA512 digest with public key N\n");

                goto bio_free;
        }

        if (EVP_DigestUpdate(md_ctx, (void *) e_b64, strlen(e_b64)) < 1) {
                printf("ERROR: updating SHA512 digest with public key E\n");

                goto bio_free;
        }

        /*
         * Allocate the memory to hold the SHA512 hash, and write the SHA512
         * hash to the "hash" byte array.
         */
        *hash = (unsigned char *) OPENSSL_malloc(EVP_MD_size(EVP_sha512()));
        if (*hash == NULL) {
                printf("ERROR: allocating memory for SHA512 hash\n");

                goto bio_free;
        }

        if (EVP_DigestFinal_ex(md_ctx, *hash, size) < 1) {
                printf("ERROR: finalizing the SHA512 hash\n");

                goto hash_free;
        }

        rc = 0;

        goto bio_free;

hash_free:
        OPENSSL_free((void *) *hash);

bio_free:
        BIO_free(n_bio);
        BIO_free(n_bio64);
        BIO_free(e_bio);
        BIO_free(e_bio64);

bn_e_free:
        BN_free(e);

bn_n_free:
        BN_free(n);

md_ctx_free:
        EVP_MD_CTX_free(md_ctx);

        return rc;
}

/*
 * Base-64 encode an OpenSSL BIGNUM.
 */
void
ossl_bn_b64(BIGNUM *bn, char **bn_b64, BIO *bio, BIO *b64)
{
        unsigned char *bn_bin;
        int bn_binlen;
        int bn_b64len;

        bn_binlen = BN_num_bytes(bn);
        bn_bin = malloc(bn_binlen);
        BN_bn2bin(bn, bn_bin);

        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

        BIO_push(b64, bio);

        BIO_write(b64, bn_bin, bn_binlen);

        bn_b64len = BIO_get_mem_data(b64, bn_b64);
        (*bn_b64)[bn_b64len] = '\0';

        free(bn_bin);
}
