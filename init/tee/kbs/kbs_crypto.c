// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "kbs.h"

/*
 * Create an OpenSSL TEE public/private key pair.
 */
int
kbs_tee_pubkey_create(EVP_PKEY **pkey, BIGNUM *n, BIGNUM *e)
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
        ret = EVP_PKEY_get_bn_param(*pkey, OSSL_PKEY_PARAM_RSA_N, &n);
        if (ret < 0 || n == NULL) {
                printf("ERROR: getting public key modulus\n");

                goto ctx_free;
        }

        ret = EVP_PKEY_get_bn_param(*pkey, OSSL_PKEY_PARAM_RSA_E, &e);
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
 * Create a SHA256 hash of the nonce and TEE public key to send to the
 * attestation server.
 */
int
kbs_nonce_pubkey_hash(char *nonce, EVP_PKEY *pkey, unsigned char **hash,
                unsigned int *size)
{
        int rc;
        EVP_MD_CTX *md_ctx;
        BIO *bio;
        BUF_MEM *bm;

        rc = -1;

        /*
         * Initialize an MD context and initialize the SHA256 digest.
         */
        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL) {
                printf("ERROR: generating SHA256 context\n");

                return rc;
        }

        if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) < 1) {
                printf("ERROR: initializing SHA256 hash\n");

                goto md_ctx_free;
        }

        /*
         * Update the digest with the data from the nonce.
         */
        if (EVP_DigestUpdate(md_ctx, (void *) nonce, strlen(nonce)) < 1) {
                printf("ERROR: updating SHA256 digest with nonce\n");

                goto md_ctx_free;
        }

        /*
         * Update the digest with the data from the TEE public key.
         *
         * To do this, we must create a OpenSSL BIO object containing the data
         * of the TEE public key. Once that BIO object is created, print the
         * TEE public key data to the object, and update the SHA256 digest with
         * the data from the public key.
         */
        bio = BIO_new(BIO_s_mem());
        if (bio == NULL) {
                printf("ERROR: initializing pkey BIO\n");

                goto md_ctx_free;
        }

        if (EVP_PKEY_print_public(bio, pkey, 0, NULL) != 1) {
                printf("ERROR: printing public key to BIO\n");

                goto bio_free;
        }

        BIO_get_mem_ptr(bio, &bm);

        if (EVP_DigestUpdate(md_ctx, (void *) bm->data, bm->length) < 1) {
                printf("ERROR: updating SHA256 hash with TEE public key\n");

                goto bio_free;
        }

        /*
         * Allocate the memory to hold the SHA256 hash, and write the SHA256
         * hash to the "hash" byte array.
         */
        *hash = (unsigned char *) OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
        if (*hash == NULL) {
                printf("ERROR: allocating memory for SHA256 hash\n");

                goto bio_free;
        }

        if (EVP_DigestFinal_ex(md_ctx, *hash, size) < 1) {
                printf("ERROR: finalizing the SHA256 hash\n");

                goto hash_free;
        }

        rc = 0;

        goto bio_free;

hash_free:
        OPENSSL_free((void *) *hash);

bio_free:
        BIO_free(bio);

md_ctx_free:
        EVP_MD_CTX_free(md_ctx);

        return rc;
}
