// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "kbs.h"

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
        int ret;

        ret = kbs_curl_post(curl, url, (void *) json_request, (void *) nonce, KBS_CURL_REQ);
        if (ret < 0) {
                printf("ERROR: could not complete KBS challenge\n");
                return -1;
        }

        return 0;
}
