// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "kbs.h"

#include "../snp_attest.h"

static void kbs_attestation_marshal(struct snp_report *, char *, BIGNUM *,
        BIGNUM *, char *);
static void kbs_attestation_marshal_tee_pubkey(char *, BIGNUM *, BIGNUM *);

/*
 * Given a TEE architecture and workload ID, write the JSON string of the
 * KBS REQUEST.
 */
int
kbs_request_marshal(char *json_request, int tee, char *workload_id)
{
        char *teestr;

        /*
         * Retrieve the KBS string equivalent of the TEE enum value.
         */
        teestr = tee_str(tee);
        if (teestr == NULL)
                return -1;

        /*
         * Build the KBS REQUEST JSON string.
         */
        sprintf(json_request,
        "{\"extra-params\":\"{\\\"workload_id\\\":\\\"%s\\\"}\",\"tee\":\"%s\",\"version\":\"0.0.0\"}",
                workload_id,
                teestr);

        return 0;
}

/*
 * Peform a KBS CHALLENGE.
 *
 * "json_request" is the JSON string of the KBS REQUEST.
 * "nonce" is the output argument to be retrieved from the attestation server.
 */
int
kbs_challenge(CURL *curl, char *url, char *json_request, char *nonce)
{
        int ret, rc;
        char *nonce_json;

        rc = -1;

        nonce_json = (char *) malloc(0x2000);
        if (nonce_json == NULL) {
                printf("ERROR: unable to allocate JSON nonce buffer\n");

                return rc;
        }

        ret = kbs_curl_post(curl, url, (void *) json_request, (void *) nonce_json, KBS_CURL_REQ);
        if (ret < 0) {
                printf("ERROR: could not complete KBS challenge\n");

                goto out;
        }

        /*
         * Parse the JSON response from the KBS server to retrieve the nonce.
         */
        if (json_parse_str(nonce, "nonce", nonce_json) < 0) {
                printf("ERROR: unable to parse nonce from server response\n");

                goto out;
        }

        rc = 0;

out:
        free(nonce_json);

        return rc;
}

/*
 * Send all required materials (attestation report, certificate chain, etc..)
 * to the attestation server for attestation.
 */
int
kbs_attest(CURL *curl, char *url, struct snp_report *report, BIGNUM *mod,
                BIGNUM *exp, char *gen)
{
        int rc;
        char *json, errmsg[200];

        rc = -1;
        json = (char *) malloc(0x1000);
        if (json == NULL) {
                printf("ERROR: unable to allocate JSON buffer\n");

                return rc;
        }

        /*
         * Marshal the kbs_types Attestation JSON struct with the given
         * attestation report and certificate chain.
         */
        kbs_attestation_marshal(report, json, mod, exp, gen);

        /*
         * Ensure the error messaging string is empty, because we will
         * eventually read this string as indicator of a cURL attestation
         * server error.
         */
        strcpy(errmsg, "");

        if (kbs_curl_post(curl, url, json, errmsg, KBS_CURL_ATTEST) < 0) {
                printf("ERROR: could not complete KBS attestation\n");

                rc = -1;
                goto out;
        }

        /*
         * If there is no error message, it can be assumed that the attestation
         * was completed successfully.
         */
        if (strcmp(errmsg, "") != 0) {
                rc = -1;
                printf("ATTESTATION ERROR: %s\n", errmsg);

                goto out;
        }

        rc = 0;

out:
        free((void *) json);

        return rc;
}

/*
 * Retrieve the secret from the KBS attestation server.
 */
int
kbs_get_key(CURL *curl, char *url, char *wid, EVP_PKEY *pkey, char *pass)
{
        int end_idx;
        char json[4096];
        char encrypted[4096], *plain;

        /*
         * The key is represented as a JSON byte list, copy this JSON list
         * string to "json".
         */
        if (kbs_curl_get(curl, url, wid, json, KBS_CURL_GET_KEY) < 0) {
                printf("ERROR: could not complete KBS passphrase retrieval\n");

                return -1;
        }

        end_idx = strlen(json) - 2;

        memcpy(encrypted, json + 1, end_idx);
        encrypted[end_idx] = '\0';

        if (rsa_pkey_decrypt(pkey, encrypted, &plain) < 0) {
                printf("ERROR: could not decrypt passphrase from KBS server\n");

                return -1;
        }

        strcpy(pass, plain);

        OPENSSL_free(plain);

        return 0;
}

/*
 * Marshal a JSON string of the kbs_types Attestation struct from the given
 * attestation report and certificate data.
 */
static void
kbs_attestation_marshal(struct snp_report *report, char *json, BIGNUM *mod,
                BIGNUM *exp, char *gen)
{
        char buf[4096], *report_hexstr;
        size_t report_hexstr_len;

        report_hexstr = (char *) malloc(0x1000);
        if (report_hexstr == NULL)
                return;

        sprintf(buf, "{");
        strcpy(json, buf);

        kbs_attestation_marshal_tee_pubkey(json, mod, exp);

        sprintf(buf, "\"tee-evidence\":\"{");
        strcat(json, buf);

        sprintf(buf, "\\\"gen\\\":\\\"%s\\\",", gen);
        strcat(json, buf);

        OPENSSL_buf2hexstr_ex(report_hexstr, 0x1000, &report_hexstr_len,
                (unsigned char *) report, sizeof(*report), '\0');
        report_hexstr[report_hexstr_len] = '\0';
        sprintf(buf, "\\\"report\\\":\\\"%s\\\",", report_hexstr);
        strcat(json, buf);

        strcat(json, "\\\"cert_chain\\\":\\\"[]\\\"}");

        strcat(json, "\"}");
}

/*
 * Marshal a JSON string of the KBS TEE public key.
 */
static void
kbs_attestation_marshal_tee_pubkey(char *json, BIGNUM *mod, BIGNUM *exp)
{
        char mod_b64[512], exp_b64[512];
        char buf[1024];

        if (mod == NULL || exp == NULL)
                return;

        BN_b64(mod, mod_b64);
        BN_b64(exp, exp_b64);

        sprintf(buf, "\"tee-pubkey\":{");
        strcat(json, buf);

        sprintf(buf, "\"alg\":\"RSA\",");
        strcat(json, buf);

        sprintf(buf, "\"k-mod\":\"%s\",", mod_b64);
        strcat(json, buf);

        sprintf(buf, "\"k-exp\":\"%s\"},", exp_b64);
        strcat(json, buf);
}
