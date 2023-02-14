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
        BIGNUM *n, *e;
        char n_b64[512], e_b64[512];

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

                goto md_ctx_free;
        }

        /*
         * base64-encode the modulus and exponents, and hash the base64 strings
         * into the SHA512 digest.
         */
        BN_b64(n, n_b64);
        BN_b64(e, e_b64);

        if (EVP_DigestUpdate(md_ctx, (void *) n_b64, strlen(n_b64)) < 1) {
                printf("ERROR: updating SHA512 digest with public key N\n");

                goto md_ctx_free;
        }

        if (EVP_DigestUpdate(md_ctx, (void *) e_b64, strlen(e_b64)) < 1) {
                printf("ERROR: updating SHA512 digest with public key E\n");

                goto md_ctx_free;
        }

        /*
         * Allocate the memory to hold the SHA512 hash, and write the SHA512
         * hash to the "hash" byte array.
         */
        *hash = (unsigned char *) OPENSSL_malloc(EVP_MD_size(EVP_sha512()));
        if (*hash == NULL) {
                printf("ERROR: allocating memory for SHA512 hash\n");

                goto md_ctx_free;
        }

        if (EVP_DigestFinal_ex(md_ctx, *hash, size) < 1) {
                printf("ERROR: finalizing the SHA512 hash\n");

                goto hash_free;
        }

        rc = 0;

        goto md_ctx_free;

hash_free:
        OPENSSL_free((void *) *hash);

md_ctx_free:
        EVP_MD_CTX_free(md_ctx);

        return rc;
}

/*
 * Using a given RSA public/private key pair, decrypt an encrypted and hex
 * encoded string of text. Store the plaintext of the encrypted text into a
 * buffer and point "plain_ptr" to said buffer.
 */
int
rsa_pkey_decrypt(EVP_PKEY *pkey, char *enc, char **plain_ptr)
{
        int rc;
        EVP_PKEY_CTX *ctx;
        char enc_bin[4096], *plain;
        size_t enc_bin_len, secret_plain_len = 4096;

        rc = -1;

        /*
         * Decode the hex-encoded string to its byte format.
         */
        if (OPENSSL_hexstr2buf_ex((unsigned char *) enc_bin, 4096, &enc_bin_len,
                        enc, '\0') != 1) {
		printf("Error converting hex to buf\n");

		return rc;
	}

        /*
         * Initialize the public key decryption context.
         */
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (ctx == NULL) {
                printf("ERROR: creation of pkey context for decryption\n");

                return rc;
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
                printf("ERROR: creation of decryption context for pkey\n");

                goto ctx_free;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
	        printf("Error setting RSA padding\n");

		goto ctx_free;
	}

        /*
         * To first get the length that the plain secret buffer should be, call
         * EVP_PKEY_decrypt() with a NULL output buffer argument. Then,
         * "secret_plain_len" will contain the proper amount of bytes to
         * allocate for the output buffer.
         */
        rc = EVP_PKEY_decrypt(ctx, NULL,
                        &secret_plain_len, (unsigned char *) enc_bin,
                        enc_bin_len);
        if (rc <= 0) {
                printf("ERROR: finding plaintext passphrase length: %d\n", rc);

                goto ctx_free;
        }

        /*
         * Allocate the output buffer using "secret_plain_len".
         */
        plain = OPENSSL_malloc(secret_plain_len);
        if (plain == NULL)
                goto ctx_free;

        /*
         * Decrypt the string using the OpenSSL RSA public key.
         */
        rc = EVP_PKEY_decrypt(ctx, (unsigned char *) plain, &secret_plain_len,
                        (unsigned char *) enc_bin, enc_bin_len);
        if (rc <= 0) {
                printf("ERROR: decrypting RSA-encrypted passphrase: %d\n", rc);
                OPENSSL_free(plain);

                goto ctx_free;
        }
        plain[secret_plain_len] = '\0';

        /*
         * Set the "plain_ptr" arg to the plaintext passphrase".
         */
        *plain_ptr = plain;

        rc = 0;

ctx_free:
        EVP_PKEY_CTX_free(ctx);

        return rc;
}

/*
 * base64-encode the contents of an OpenSSL BIGNUM.
 */
void
BN_b64(BIGNUM *bn, char *str)
{
        BIO *bio;
	BIO *b64;
	char *bn_bin;
	char *bn_b64;
	int bn_binlen;
	int bn_b64len;

        /*
         * Encode the BIGNUM contents to binary.
         */
	bn_binlen = BN_num_bytes(bn);
	bn_bin = malloc(bn_binlen);
	BN_bn2bin(bn, (unsigned char *) bn_bin);

        /*
         * Write the binary-encoded string to to a base64-configured OpenSSL
         * BIO.
         */
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_new(BIO_s_mem());
	BIO_push(b64, bio);
	BIO_write(b64, bn_bin, bn_binlen);
	BIO_flush(b64);

        /*
         * Retrieve the base64-encoded contents of the BIO, null-terminate the
         * string, and copy those contents to the output string.
         */
	bn_b64len = BIO_get_mem_data(b64, &bn_b64);
	bn_b64[bn_b64len] = '\0';

        strcpy(str, bn_b64);

        /*
         * Cleanup OpenSSL data structures.
         */
	BIO_free(b64);
	BIO_free(bio);
	free(bn_bin);
}
