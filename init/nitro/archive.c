// SPDX-License-Identifier: Apache-2.0

#include <stddef.h>
#include <stdlib.h>

#include <archive.h>
#include <archive_entry.h>

#include "include/archive.h"

/*
 * Create an archive object for reading streaming archives. Enclaves' rootfs is
 * written from the hypervisor in tar format and stored in memory (rather than a
 * file).
 */
static struct archive *reader_init(void *buf, size_t size)
{
    struct archive *r;
    int ret;

    r = archive_read_new();
    if (r == NULL) {
        printf("init reader failed\n");
        return NULL;
    }

    // Archive is in tar format.
    ret = archive_read_support_format_tar(r);
    if (ret != ARCHIVE_OK) {
        printf("reader cannot support tar format\ncause: %s\n",
               archive_error_string(r));
        return NULL;
    }

    ret = archive_read_open_memory(r, buf, size);
    if (ret != ARCHIVE_OK) {
        printf("reader cannot open file\ncause: %s\n", archive_error_string(r));
        return NULL;
    }

    return r;
}

/*
 * Extract the tarball from the reader (that is, the memory buffer that read the
 * rootfs archive from the hypervisor vsock) and write it to the enclave's file
 * system.
 */
static int extract(struct archive *r, struct archive *w)
{
    struct archive_entry *entry;
    const char *path;
    const void *buf;
    int64_t offset;
    size_t size;
    int ret;

    while ((ret = archive_read_next_header(r, &entry)) != ARCHIVE_EOF) {
        // Ensure the archive header read from the memory is valid.
        if (ret != ARCHIVE_OK) {
            printf("error reading archive header\ncause: %s\n",
                   archive_error_string(r));
            goto err;
        }

        path = archive_entry_pathname(entry);

        // Write the header to the filesystem.
        ret = archive_write_header(w, entry);
        if (ret != ARCHIVE_OK) {
            printf("error writing %s header\ncause: %s\n", path,
                   archive_error_string(w));
            goto err;
        }

        // Read archive data from the reader and write them to the filesystem.
        while ((ret = archive_read_data_block(r, &buf, &size, &offset)) !=
               ARCHIVE_EOF) {
            if (ret != ARCHIVE_OK) {
                printf("error reading %s archive data block\ncause: %s\n", path,
                       archive_error_string(r));
                goto err;
            }

            ret = archive_write_data_block(w, buf, size, offset);
            if (ret != ARCHIVE_OK) {
                printf("error writing %s archive data block\ncause: %s\n", path,
                       archive_error_string(w));
                goto err;
            }
        }

        // Notify the writer that writes are finished for this archive entry.
        ret = archive_write_finish_entry(w);
        if (ret != ARCHIVE_OK) {
            printf("error finishing %s entry\ncause: %s\n", path,
                   archive_error_string(w));
            goto err;
        }
    }

    return 0;

err:
    return -ret;
}

/*
 * Free the archive reader and writer.
 */
static void archive_cleanup(struct archive *r, struct archive *w)
{
    if (r != NULL) {
        archive_read_close(r);
        archive_read_free(r);
    }

    if (w != NULL) {
        archive_write_close(w);
        archive_write_free(w);
    }
}

/*
 * Extract the archive written to memory and write it to the enclave file
 * system.
 */
int archive_extract(void *buf, size_t size)
{
    struct archive *reader, *writer;
    int ret;

    reader = reader_init(buf, size);
    if (reader == NULL)
        return -1;

    writer = archive_write_disk_new();
    if (writer == NULL) {
        archive_cleanup(reader, NULL);
        return -1;
    }

    ret = extract(reader, writer);
    archive_cleanup(reader, writer);

    return ret;
}
