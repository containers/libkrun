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

#include "snp_attest.h"
#include "kbs/kbs.h"

#define NONCE_MAX       1024
#define JSON_MAX        1024

static int snp_get_ext_report(const uint8_t *, size_t, struct snp_report *,
        uint8_t **, size_t *);
static int SNP_ATTEST_ERR(char *);

int
snp_attest(char *pass, char *url, char *wid)
{
        CURL *curl;
        char nonce[NONCE_MAX], json[JSON_MAX];
        struct snp_report report;
        uint8_t *certs;
        size_t certs_size;

        if (kbs_request_marshal(json, TEE_SNP, wid) < 0)
                return SNP_ATTEST_ERR("Unable to marshal KBS REQUEST");

        curl = curl_easy_init();
        if (curl == NULL)
                return SNP_ATTEST_ERR("Unable to initialize cURL instance");

        if (kbs_challenge(curl, url, json, nonce) < 0)
                return SNP_ATTEST_ERR("Unable to retrieve nonce from server");

        if (snp_get_ext_report((uint8_t *) nonce, strlen(nonce) + 1, &report,
                        &certs, &certs_size) != EXIT_SUCCESS)
                return SNP_ATTEST_ERR("Unable to retrieve attestation report");

        return 0;
}

/*
 * A function for the SNP_GET_EXT_REPORT ioctl.
 *
 * SNP_GET_EXT_REPORT fills both the attestation report and the certificate
 * data.
 */
static int
snp_get_ext_report(const uint8_t *data, size_t data_size,
        struct snp_report *report, uint8_t **certs, size_t *certs_size)
{
        int rc = EXIT_FAILURE;
        int fd = -1;
        struct snp_ext_report_req req;
        struct snp_report_resp resp;
        struct snp_guest_request_ioctl guest_req;
        struct msg_report_resp *report_resp = (struct msg_report_resp *)&resp.data;
        struct cert_table certs_data;
        size_t page_size = 0, nr_pages = 0;

        /*
         * The kernel will attempt to fill the report, certs, and certs_size,
         * Therefore, none of these values can be NULL.
         */
        if (!report || !certs || !certs_size) {
                printf("report || certs || certs_size == NULL\n");
                rc = EINVAL;

                goto out;
        }

        /*
         * We will be filling the user_data field of the request with "data".
         * Ensure that the data is valid and can fit in the user_data field.
         */
        if (data && (data_size > sizeof(req.data.user_data) || data_size == 0)) {
                rc = EINVAL;

                goto out;
        }

        /*
         * Initialize data structures.
         */
        memset(&req, 0, sizeof(req));

        /*
         * Set the request's certs_address to an invalid address in order to
         * allow the kernel to fill this address with a valid certificate
         * buffer address.
         */
        req.certs_address = (__u64) -1;

        /*
         * Copy the data into user_data if it exists.
         */
        if (data)
                memcpy(&req.data.user_data, data, data_size);

        memset(&resp, 0, sizeof(resp));

        memset(&guest_req, 0, sizeof(guest_req));
        guest_req.msg_version = 1;
        guest_req.req_data = (__u64) &req;
        guest_req.resp_data = (__u64) &resp;

        memset(&certs_data, 0, sizeof(certs_data));

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
         * Query the size of the stored certificates.
         *
         * For some background, this ioctl is done in two phases. In the first
         * phase (with certs_address == -1 and certs_size == 0), the kernel's
         * only responsibility is to set the correct certs_size so that the
         * user program can allocate enough memory to hold the certificate
         * buffer. The second phase is where the filling-in of report + certs
         * data is performed.
         *
         */
        errno = 0;
        rc = ioctl(fd, SNP_GET_EXT_REPORT, &guest_req);
        if (rc == -1 && guest_req.fw_err != 0x100000000) {
                rc = errno;
                perror("ioctl");
                fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
                fprintf(stderr, "report error %#x\n", report_resp->status);
                fprintf(stderr, "certs_len %#x\n", req.certs_len);

                goto out_close;
        }

        /*
         * If the kernel reports back a changed certs_len of 0, that indicates
         * that there are no certificates to be found. Return an error if so.
         */
        if (req.certs_len == 0) {
                fprintf(stderr, "The cert chain storage is empty.\n");
                rc = ENODATA;

                goto out_close;
        }

        /*
         * Allocate the needed amount of memory for the certificates. Note that
         * the size of the certificate buffer must be on a 4KB page boundary.
         */
        page_size = sysconf(_SC_PAGESIZE);
        nr_pages = req.certs_len/page_size;
        if (req.certs_len % page_size != 0)
                nr_pages++;

        certs_data.entry = calloc(page_size, nr_pages);
        if (!certs_data.entry) {
                rc = ENOMEM;
                errno = rc;
                perror("calloc");

                goto out_close;
        }

        /*
         * Retrieve the SNP attestation report and certificate chain.
         */
        req.certs_address = (__u64)certs_data.entry;
        errno = 0;
        rc = ioctl(fd, SNP_GET_EXT_REPORT, &guest_req);
        if (rc == -1) {
                rc = errno;
                perror("ioctl");
                fprintf(stderr, "errno is %u\n", errno);
                fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
                fprintf(stderr, "report error %x\n", report_resp->status);

                goto out_free;
        }

        /*
         * Ensure that the report was successfully generated.
         */
        if (report_resp->status != 0 ) {
                fprintf(stderr, "firmware error %x\n", report_resp->status);
                rc = report_resp->status;

                goto out_free;
        } else if (report_resp->report_size > sizeof(*report)) {
                fprintf(stderr, "report size is %u bytes (expected %lu)!\n",
                        report_resp->report_size, sizeof(*report));
                rc = EFBIG;

                goto out_free;
        }

        /*
         * Copy the report + certs data.
         */
        memcpy(report, &report_resp->report, report_resp->report_size);
        *certs = (uint8_t *) certs_data.entry;
        *certs_size = req.certs_len;
        rc = EXIT_SUCCESS;

out_free:
        if (rc != EXIT_SUCCESS && certs_data.entry) {
                free(certs_data.entry);
                certs_data.entry = NULL;
        }

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
