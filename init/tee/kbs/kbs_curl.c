// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

#include "kbs.h"

static CURLcode kbs_curl_set_headers(CURL *, char *);
static int KBS_CURL_ERR(char *);
size_t curl_write(void *, size_t, size_t, void *);

static int kbs_curl_post_request(CURL *, char *, char *, char *);

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

        /*
         * Neither the input or output strings should be invalid/NULL.
         */
        if (!in)
                return KBS_CURL_ERR("Input argument NULL");

        if (!out)
                return KBS_CURL_ERR("Output argument NULL");

        /*
         * Specify the following cURL operations/attributes:
         *      * Headers
         *      * POST operation
         *      * Write function
         */
        code = kbs_curl_set_headers(curl, NULL);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_HTTPHEADER");

        code = curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POST");

        code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_WRITEFUNCTION");

        /*
         * Based on the operation TYPE, there will need to be some additional
         * cURL attributes set. These will also perform the cURL request.
         */
        switch (type) {
        case KBS_CURL_REQ:
                return kbs_curl_post_request(curl, url, in, out);
        default:
                return KBS_CURL_ERR("Type argument invalid");
        }
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
        char session_buf[100];

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
 * POST a KBS REQUEST and attempt to retrieve a nonce from the attestation
 * server.
 */
static int
kbs_curl_post_request(CURL *curl, char *url, char *req, char *nonce)
{
        CURLcode code;
        char req_url[100];

        /*
         * Set the cURL POST URL to $URL/kbs/v0/auth.
         */
        sprintf(req_url, "%s/kbs/v0/auth", url);

        code = curl_easy_setopt(curl, CURLOPT_URL, req_url);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_URL");

        /*
         * Set the KBS REQUEST size and data.
         */
        code = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(req));
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POSTFIELDSIZE");

        code = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POSTFIELDS");

        /*
         * We would like the nonce written to the "nonce" argument.
         */
        code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, nonce);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_WRITEDATA");

        code = curl_easy_perform(curl);
        if (code != CURLE_OK && code != CURLE_WRITE_ERROR)
                return KBS_CURL_ERR("CURL_EASY_PERFORM");

        return 0;
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
curl_write(void *data, size_t size, size_t nmemb, void *userp)
{
        strcpy((char *) userp, (char *) data);

        return size;
}
