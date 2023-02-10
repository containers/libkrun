// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "kbs.h"

/*
 * Return the string identifier of the inputted TEE architecture.
 */
char *
tee_str(int tee)
{
        switch (tee) {
        case TEE_SEV:
                return "sev";
        case TEE_SGX:
                return "sgx";
        case TEE_SNP:
                return "snp";
        case TEE_TDX:
                return "tdx";

        /*
         * No other TEE architecture is supported.
         */
        default:
                printf("ERROR: tee_str(): Invalid input\n");
                return NULL;
        }
}

/*
 * Parse a given string of cURL cookie data and find the label indicated by the
 * "label" argument. This function is essentially a search of a substring
 * within a given string.
 */
char *
find_cookie(char *cookie_data, char *label)
{
        char *cookie_ptr;
        size_t label_len, cookie_len;

        label_len = strlen(label);
        cookie_len = strlen(cookie_data);

        cookie_ptr = cookie_data;
        for (int i = 0; i < (cookie_len - label_len); i++, cookie_ptr++) {
                if (strncmp(cookie_ptr, label, label_len) == 0)
                        return cookie_ptr;
        }

        return NULL;
}

/*
 * From a label in a cURL cookie string, parse its associated value.
 */
int
read_cookie_val(char *label, char *buf)
{
        char *ptr;
        int ws;

        ws = 0;
        ptr = label;
        for (ptr = label; *ptr != '\0'; ptr++) {
                if (*ptr == ' ' || *ptr == '\t')
                        ws = 1;
                else if (ws == 1) {
                        strcpy(buf, ptr);

                        return 0;
                }
        }

        return -1;
}
