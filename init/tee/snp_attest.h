// SPDX-License-Identifier: Apache-2.0

#ifndef _SNP_ATTEST
#define _SNP_ATTEST

#include <stdint.h>

#include <uuid/uuid.h>

#define SEV_GUEST_DEV "/dev/sev-guest"

/*
 * Cryptographic signature (should be signed by the VCEK).
 */
struct signature {
	uint8_t r[72];
        uint8_t s[72];
	uint8_t reserved[512-144];
};

/*
 * Structure containing the security version numbers of each component in the
 * Trusted Computing Base (TCB) of the SNP firmware.
 */
union tcb_version {
	struct {
                uint8_t boot_loader;
		uint8_t tee;
		uint8_t reserved[4];
		uint8_t snp;
		uint8_t microcode;
	};
	uint64_t raw;
};

/*
 * An array of certificates. Consult the AMD SEV GHCB document to understand how
 * this table should be built and parsed.
 */
struct cert_table {
        struct cert_table_entry {
                uuid_t guid;
                uint32_t offset;
                uint32_t len;
        } *entry;
};

/*
 * SNP attestation report structure. Based off of the attestation report
 * structure described in firmware version 1.52.
 */
struct snp_report {
        uint32_t                version;
        uint32_t                guest_svn;
        uint64_t                policy;
        uint8_t                 family_id[16];
        uint8_t                 image_id[16];
        uint32_t                vmpl;
        uint32_t                signature_algo;
        union tcb_version      current_tcb;

        /*
         * TODO: Change to a "struct platform_info".
         */
        uint64_t                platform_info;

        uint32_t                author_key_en : 1;
        uint32_t                _reserved_0 : 31;
        uint32_t                _reserved_1;
        uint8_t                 report_data[64];
        uint8_t                 measurement[48];
        uint8_t                 host_data[32];
        uint8_t                 id_key_digest[48];
        uint8_t                 author_key_digest[48];
        uint8_t                 report_id[32];
        uint8_t                 report_id_ma[32];
        union tcb_version       reported_tcb;
        uint8_t                 _reserved_2[24];
        uint8_t                 chip_id[64];
        union tcb_version      committed_tcb;
        uint8_t                 current_build;
        uint8_t                 current_minor;
        uint8_t                 current_major;
        uint8_t                 _reserved_3;
        uint8_t                 committed_build;
        uint8_t                 committed_minor;
        uint8_t                 committed_major;
        uint8_t                 _reserved_4;
        union tcb_version      launch_tcb;
        uint8_t                 _reserved_5[168];
        struct signature        signature;
};

/*
 * Response from the SNP_GET_EXT_REPORT ioctl.
 */
struct msg_report_resp {
	uint32_t status;
	uint32_t report_size;
	uint8_t  reserved[0x20-0x8];
	struct snp_report report;
};

// snp_attest.c
int snp_attest(char *, char *, char *, char *);

#endif /* _SNP_ATTEST */
