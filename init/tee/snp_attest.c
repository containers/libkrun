// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stddef.h>

#include "snp_attest.h"
#include "kbs/kbs.h"

#define NONCE_MAX       1024
#define JSON_MAX        1024

static int SNP_ATTEST_ERR(char *);

int
snp_attest(char *pass, char *url, char *wid)
{
        CURL *curl;
        char nonce[NONCE_MAX], json[JSON_MAX];

        if (kbs_request_marshal(json, TEE_SNP, wid) < 0)
                return SNP_ATTEST_ERR("Unable to marshal KBS REQUEST");

        curl = curl_easy_init();
        if (curl == NULL)
                return SNP_ATTEST_ERR("Unable to initialize cURL instance");

        if (kbs_challenge(curl, url, json, nonce) < 0)
                return SNP_ATTEST_ERR("Unable to retrieve nonce from server");

        return 0;
}

static int
SNP_ATTEST_ERR(char *errmsg)
{
        printf("SNP ATTEST ERROR: %s\n", errmsg);

        return -1;
}
