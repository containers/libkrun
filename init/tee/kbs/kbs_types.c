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

static void kbs_attestation_marshal(struct snp_report *, uint8_t *, size_t,
                                        char *, BIGNUM *, BIGNUM *);
static void kbs_attestation_marshal_tcb(char *, char *, union tcb_version *);
static void kbs_attestation_marshal_signature(char *, struct signature *);
static void kbs_attestation_marshal_bytes(char *, char *, uint8_t *, size_t);
static void kbs_attestation_marshal_certs(char *, uint8_t *, size_t);
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

        nonce_json = (char *) malloc(0x1000);
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
kbs_attest(CURL *curl, char *url, struct snp_report *report, uint8_t *certs,
                size_t certs_size, BIGNUM *mod, BIGNUM *exp)
{
        int rc;
        char *json, errmsg[200];

        rc = -1;
        json = (char *) malloc(0x7000);
        if (json == NULL) {
                printf("ERROR: unable to allocate JSON buffer\n");

                return rc;
        }

        /*
         * Marshal the kbs_types Attestation JSON struct with the given
         * attestation report and certificate chain.
         */
        kbs_attestation_marshal(report, certs, certs_size, json, mod, exp);

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
kbs_attestation_marshal(struct snp_report *report, uint8_t *certs,
        size_t certs_size, char *json, BIGNUM *mod, BIGNUM *exp)
{
        char buf[4096];

        sprintf(buf, "{");
        strcpy(json, buf);

        kbs_attestation_marshal_tee_pubkey(json, mod, exp);

        sprintf(buf, "\"tee-evidence\":\"{\\\"report\\\":\\\"{");
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"version\\\\\\\":%u,", report->version);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"guest_svn\\\\\\\":%u,", report->guest_svn);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"policy\\\\\\\":%lu,", report->policy);
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "family_id",
                (uint8_t *) report->family_id, 16);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "image_id",
                (uint8_t *) report->image_id, 16);
        strcat(json, ",");

        sprintf(buf, "\\\\\\\"vmpl\\\\\\\":%u,", report->vmpl),
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"sig_algo\\\\\\\":%u,", report->signature_algo);
        strcat(json, buf);

        kbs_attestation_marshal_tcb(json, "current_tcb", &report->current_tcb);
        strcat(json, ",");

        sprintf(buf, "\\\\\\\"plat_info\\\\\\\":%lu,", report->platform_info);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"_author_key_en\\\\\\\":%u,",
                report->author_key_en);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"_reserved_0\\\\\\\":%u,", report->_reserved_0);
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "report_data",
                (uint8_t *) report->report_data, 64);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "measurement",
                (uint8_t *) report->measurement, 48);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "host_data",
                (uint8_t *) report->host_data, 32);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "id_key_digest",
                (uint8_t *) report->id_key_digest, 48);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "author_key_digest",
                (uint8_t *) report->author_key_digest, 48);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "report_id",
                (uint8_t *) report->report_id, 32);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "report_id_ma",
                (uint8_t *) report->report_id_ma, 32);
        strcat(json, ",");

        kbs_attestation_marshal_tcb(json, "reported_tcb",
                &report->reported_tcb);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "_reserved_1",
                (uint8_t *) report->_reserved_1, 24);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "chip_id",
                (uint8_t *) report->chip_id, 64);
        strcat(json, ",");

        kbs_attestation_marshal_tcb(json, "committed_tcb",
                &report->committed_tcb);
        strcat(json, ",");

        sprintf(buf, "\\\\\\\"current_build\\\\\\\":%u,",
                report->current_build);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"current_minor\\\\\\\":%u,",
                report->current_minor);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"current_major\\\\\\\":%u,",
                report->current_major);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"_reserved_2\\\\\\\":%u,", report->_reserved_2);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"committed_build\\\\\\\":%u,",
                report->committed_build);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"committed_minor\\\\\\\":%u,",
                report->committed_minor);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"committed_major\\\\\\\":%u,",
                report->committed_major);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"_reserved_3\\\\\\\":%u,", report->_reserved_3);
        strcat(json, buf);

        kbs_attestation_marshal_tcb(json, "launch_tcb", &report->launch_tcb);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "_reserved_4",
                (uint8_t *) report->_reserved_4, 168);
        strcat(json, ",");

        kbs_attestation_marshal_signature(json, &report->signature);

        strcat(json, "}\\\",");

        kbs_attestation_marshal_certs(json, certs, certs_size);
        strcat(json, "\"}");
}

/*
 * Marshal a JSON string of a SNP TCB Version struct.
 */
static void
kbs_attestation_marshal_tcb(char *json, char *name, union tcb_version *tcb)
{
        char buf[4096];

        sprintf(buf, "\\\\\\\"%s\\\\\\\":{", name);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"boot_loader\\\\\\\":%u,", tcb->boot_loader);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"tee\\\\\\\":%u,", tcb->tee);
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "reserved", tcb->reserved, 4);
        strcat(json, ",");

        sprintf(buf, "\\\\\\\"snp\\\\\\\":%u,", tcb->snp);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"microcode\\\\\\\":%u}", tcb->microcode);
        strcat(json, buf);

        return;
}

/*
 * Marshal a JSON list of an array of bytes.
 */
static void
kbs_attestation_marshal_bytes(char *json, char *label, uint8_t *data, size_t sz)
{
        uint8_t byte;
        char buf[4096];

        sprintf(buf, "\\\\\\\"%s\\\\\\\":[", label);
        strcat(json, buf);

        for (int i = 0; i < sz; i++) {
                byte = data[i];

                sprintf(buf, "%u", byte);
                if (i < (sz - 1))
                        strcat(buf, ",");

                strcat(json, buf);
        }

        strcat(json, "]");
}

/*
 * Marshal a JSON string of an SNP signature.
 */
static void
kbs_attestation_marshal_signature(char *json, struct signature *sig)
{
        char buf[4096];

        sprintf(buf, "\\\\\\\"signature\\\\\\\":{");
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "r", sig->r, 72);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "s", sig->s, 72);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "_reserved", sig->reserved, 368);

        strcat(json, "}");
}

/*
 * Marshal a JSON string of an SNP certificate chain. This function is almost
 * identical to kbs_attestation_marshal_bytes() with some slight tweaks to the
 * format of the "cert_chain" label and such.
 */
static void
kbs_attestation_marshal_certs(char *json, uint8_t *certs, size_t size)
{
        size_t i;
        char buf[128];

        strcat(json, "\\\"cert_chain\\\":\\\"[");

        for (i = 0; i < size; i++) {
                sprintf(buf, "%u", certs[i]);
                if (i < (size - 1))
                        strcat(buf, ", ");

                strcat(json, buf);
        }

        strcat(json, "]\\\"}");
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
