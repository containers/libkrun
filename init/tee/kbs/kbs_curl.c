// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

#include "kbs.h"

static CURLcode kbs_curl_set_headers(CURL *, char *);
static int KBS_CURL_ERR(char *);
size_t curl_wr(void *, size_t, size_t, void *);

/*
 * Complete a cURL POST request. POST the "in" string and retrieve the contents
 * of the POST request "out" string.
 *
 * Depending on the type of request, some extra headers may need to be set. 
 * For example, on a KBS REQUEST, no session ID has been retrieved from the
 * attestation server so far. Yet, during a KBS_ATTEST request, a session ID
 * has been given from the server and must be added to the headers.
 */
int
kbs_curl_post(CURL *curl, char *url, char *in, char *out, int type)
{
        CURLcode code;
        struct curl_slist *cks;
        char full_url[256], *session_id_label, session_id[256];

        /*
         * Neither the input or output strings should be invalid/NULL.
         */
        if (!in)
                return KBS_CURL_ERR("Input argument NULL");

        if (!out)
                return KBS_CURL_ERR("Output argument NULL");

        if (curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POST");

        if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_wr) != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_WRITEFUNCTION");

        /*
         * If the operation being completed is a KBS REQUEST, then this is the
         * initial request to the attestation server, and there is no session
         * ID to make note of. Otherwise, the session ID has been established
         * and must be parsed from the cURL cookies data.
         */
        cks = NULL;
        if (type == KBS_CURL_REQ) {
                sprintf(full_url, "%s/kbs/v0/auth", url);

                if (curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "") != CURLE_OK)
                        return KBS_CURL_ERR("CURLOPT_COOKIEFILE");

                if (kbs_curl_set_headers(curl, NULL) != CURLE_OK)
                        return KBS_CURL_ERR("CURLOPT_HTTPHEADER");
        } else {
                sprintf(full_url, "%s/kbs/v0/attest", url);

                if (curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cks)
                                != CURLE_OK)
                        return KBS_CURL_ERR("CURLOPT_COOKIELIST");

                session_id_label = NULL;
                while (cks) {
                        session_id_label = find_cookie(cks->data, "session_id");

                        if (session_id_label)
                                break;
                        cks = cks->next;
                }

                if (session_id_label == NULL)
                        return KBS_CURL_ERR("No session_id cookie found");

                if (read_cookie_val(session_id_label, session_id) < 0)
                        return KBS_CURL_ERR("No session_id value for cookie");

                if (kbs_curl_set_headers(curl, (char *) session_id) != CURLE_OK)
                        return KBS_CURL_ERR("CURLOPT_HTTPHEADER");
        }

        if (curl_easy_setopt(curl, CURLOPT_URL, full_url) != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_URL");

        /*
         * This is a cURL POST request that will write data to the "out"
         * argument. "out" is expected to have been allocated beforehand and
         * able to hold the full response from the attestation server.
         */
        if (curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(in))
                        != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POSTFIELDSIZE");

        if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, in) != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POSTFIELDS");

        if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, out) != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_WRITEDATA");

        code = curl_easy_perform(curl);
        if (code != CURLE_OK && code != CURLE_WRITE_ERROR)
                return KBS_CURL_ERR("CURL_EASY_PERFORM");

        return 0;
}

/*
 * Set the cURL headers. If the session args is not NULL, that indicates that
 * the session ID has been retrieved from attestation server before, and that
 * session ID should be included in the headers.
 */
static CURLcode
kbs_curl_set_headers(CURL *curl, char *session)
{
        struct curl_slist *slist;
        char session_buf[512];

        slist = NULL;
        slist = curl_slist_append(slist, "Accept: application/json");
        slist = curl_slist_append(slist,
                "Content-Type: application/json; charset=utf-8");

        /*
         * Add the session ID cookie if the session ID exists.
         */
        if (session) {
                sprintf(session_buf, "Cookie: session_id=%s", session);
                curl_slist_append(slist, session_buf);
        }

        /*
         * Set the headers.
         */
        return curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
}

/*
 * Based on the given cURL error, print the KBS error and return an error
 * indicator.
 */
static int
KBS_CURL_ERR(char *errmsg)
{
        printf("ERROR (kbs_curl_post): %s\n", errmsg);

        return -1;
}

/*
 * Simple strcpy() for attestation server responses. Required by a cURL
 * operation that writes data.
 */
size_t
curl_wr(void *data, size_t size, size_t nmemb, void *userp)
{
        strcpy((char *) userp, (char *) data);

        return size;
}
