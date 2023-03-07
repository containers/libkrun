// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/ioctl.h>

#include <linux/sev-guest.h>

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "snp_attest.h"
#include "kbs/kbs.h"

#define NONCE_MAX       1024
#define JSON_MAX        1024
#define GEN_MAX         32

static int snp_get_report(const uint8_t *, size_t, struct snp_report *);
static int SNP_ATTEST_ERR(char *);
static void json_fmt(char *);

int
snp_attest(char *pass, char *url, char *wid, char *tee_data)
{
        CURL *curl;
        char nonce[NONCE_MAX], json[JSON_MAX], gen[GEN_MAX];
        struct snp_report report;
        EVP_PKEY *pkey;
        BIGNUM *n, *e;
        unsigned int hash_size;
        uint8_t *hash;

        if (kbs_request_marshal(json, TEE_SNP, wid) < 0)
                return SNP_ATTEST_ERR("Unable to marshal KBS REQUEST");

        curl = curl_easy_init();
        if (curl == NULL)
                return SNP_ATTEST_ERR("Unable to initialize cURL instance");

        if (kbs_challenge(curl, url, json, nonce) < 0)
                return SNP_ATTEST_ERR("Unable to retrieve nonce from server");

        json_fmt(tee_data);
        if (json_parse_str(gen, "gen", tee_data) < 0)
                return SNP_ATTEST_ERR("Unable to retrieve SNP generation");

        n = e = NULL;
        if (kbs_tee_pubkey_create(&pkey, &n, &e) < 0)
                return SNP_ATTEST_ERR("Unable to create TEE public key");

        if (kbs_nonce_pubkey_hash(nonce, pkey, &hash, &hash_size) < 0)
                return SNP_ATTEST_ERR("Unable to hash nonce and public key");

        if (snp_get_report(hash, hash_size, &report) != EXIT_SUCCESS)
                return SNP_ATTEST_ERR("Unable to retrieve attestation report");

        if (kbs_attest(curl, url, &report, n, e, gen) < 0)
                return SNP_ATTEST_ERR("Unable to complete KBS ATTESTATION");

        curl_easy_reset(curl);

        if (kbs_get_key(curl, url, wid, pkey, pass) < 0)
                return SNP_ATTEST_ERR("Unable to retrieve passphrase");

        return 0;
}

/*
 * A function for the SNP_GET_REPORT ioctl.
 *
 * SNP_GET_REPORT fills both the attestation report and the certificate
 * data.
 */
static int
snp_get_report(const uint8_t *data, size_t data_sz, struct snp_report *report)
{
        int rc = EXIT_FAILURE;
        int fd = -1;
        struct snp_report_req req;
        struct snp_report_resp resp;
        struct snp_guest_request_ioctl guest_req;
        struct msg_report_resp *report_resp = (struct msg_report_resp *)&resp.data;

        /*
         * The kernel will attempt to fill the report, certs, and certs_size,
         * Therefore, none of these values can be NULL.
         */
        if (report == NULL) {
                printf("report is NULL\n");
                rc = EINVAL;

                goto out;
        }

        /*
         * We will be filling the user_data field of the request with "data".
         * Ensure that the data is valid and can fit in the user_data field.
         */
        if (data && (data_sz > sizeof(req.user_data) || data_sz == 0)) {
                rc = EINVAL;

                goto out;
        }

        /*
         * Initialize data structures.
         */
        memset(&req, 0, sizeof(req));

        /*
         * Copy the data into user_data if it exists.
         */
        if (data)
                memcpy(&req.user_data, data, data_sz);

        memset(&resp, 0, sizeof(resp));

        memset(&guest_req, 0, sizeof(guest_req));
        guest_req.msg_version = 1;
        guest_req.req_data = (__u64) &req;
        guest_req.resp_data = (__u64) &resp;

        /*
         * Open the SEV guest device.
         */
        errno = 0;
        fd = open(SEV_GUEST_DEV, O_RDWR);
        if (fd == -1) {
                rc = errno;
                perror("open");

                goto out;
        }

        /*
         * Retrieve the SNP attestation report.
         */
        errno = 0;
        rc = ioctl(fd, SNP_GET_REPORT, &guest_req);
        if (rc == -1) {
                rc = errno;
                perror("ioctl");
                fprintf(stderr, "errno is %u\n", errno);
                fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
                fprintf(stderr, "report error %x\n", report_resp->status);

                goto out_close;
        }

        /*
         * Ensure that the report was successfully generated.
         */
        if (report_resp->status != 0 ) {
                fprintf(stderr, "firmware error %x\n", report_resp->status);
                rc = report_resp->status;

                goto out_close;
        } else if (report_resp->report_size > sizeof(*report)) {
                fprintf(stderr, "report size is %u bytes (expected %lu)!\n",
                        report_resp->report_size, sizeof(*report));
                rc = EFBIG;

                goto out_close;
        }

        /*
         * Copy the report + certs data.
         */
        memcpy(report, &report_resp->report, report_resp->report_size);
        rc = EXIT_SUCCESS;

out_close:
        if (fd > 0) {
                close(fd);
                fd = -1;
        }
out:
        return rc;
}

static int
SNP_ATTEST_ERR(char *errmsg)
{
        printf("SNP ATTEST ERROR: %s\n", errmsg);

        return -1;
}

/*
 * String format an unformatted JSON string:
 *
 * For example, this string:
 *      "{\"test\":\"123\"}"
 *
 * Would become:
 *      "{"test":"123"}"
 */
static void
json_fmt(char *str)
{
        char cpy[strlen(str)];
        size_t sz, cpy_idx;

        sz = strlen(str);
        cpy_idx = 0;

        for (int i = 0; i < sz; i++) {
                if (str[i] != '\\')
                        cpy[cpy_idx++] = str[i];
        }
        cpy[cpy_idx] = '\0';

        strcpy(str, cpy);
}
