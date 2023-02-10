// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

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
