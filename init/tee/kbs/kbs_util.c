// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "kbs.h"
#include "../../jsmn.h"

#define MAX_TOKENS 16384

static int label_find(char *, char *);

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

/*
 * Given a JSON string and a "label", parse the string associated with that
 * label and write the contents to "out".
 */
int
json_parse_str(char *out, char *label, char *json)
{
        int ntokens, eq, rc;
        jsmn_parser parser;
        jsmntok_t *tokens, *curr, *next;
        char *val;
        int len;

        rc = -1;

        tokens = (jsmntok_t *) malloc (MAX_TOKENS * sizeof(jsmntok_t));
        if (tokens == NULL) {
                printf("ERROR: unable to allocate JSON string\n");

                return rc;
        }

        jsmn_init(&parser);

        ntokens = jsmn_parse(&parser, json, strlen(json), tokens, MAX_TOKENS);
        if (ntokens <= 0) {
                printf("ERROR: unable to find any tokens in KBS challenge\n");

                goto out;
        }

        /*
         * Traverse each token of the JSON string.
         */
        for (int i = 0; i < ntokens - 1; i++) {
                curr = &tokens[i];
                next = &tokens[i + 1];

                /*
                 * Only interested in reading a string.
                 */
                if (curr->type != JSMN_STRING)
                        continue;

                /*
                 * Compare the current token with the label being searched for.
                 */
                eq = label_find(label, json + curr->start);
                if (eq && next->type == JSMN_STRING) {
                        /*
                         * Found the string associated with the label, calculate
                         * its beginning and ending indexes within the JSON
                         * string and copy the contents over to "out".
                         */
                        val = json + next->start;
                        len = next->end - next->start;

                        memcpy((void *) out, (void *) val, len);
                        rc = 0;

                        goto out;
                }

        }

out:
        free((void *) tokens);

        return rc;
}

static int
label_find(char *label, char *str)
{
        size_t label_sz;

        label_sz = strlen(label);

        for (int i = 0; i < label_sz; i++) {
                if (label[i] != str[i])
                        return 0;
                if (label[i] != '\0')
                        continue;

        }

        return 1;
}
