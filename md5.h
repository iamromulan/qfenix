/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __MD5_H__
#define __MD5_H__

#include <stdint.h>
#include <stddef.h>

#define MD5_DIGEST_LENGTH 16
#define MD5_DIGEST_STRING_LENGTH 33

typedef struct {
	uint32_t state[4];
	uint32_t count[2];
	uint8_t buffer[64];
} md5_ctx_t;

void md5_init(md5_ctx_t *ctx);
void md5_update(md5_ctx_t *ctx, const void *data, size_t len);
void md5_final(md5_ctx_t *ctx, uint8_t digest[MD5_DIGEST_LENGTH]);

/* Compute MD5 of a file, returns 0 on success, -1 on error */
int md5_file(const char *filename, uint8_t digest[MD5_DIGEST_LENGTH]);

/* Convert MD5 digest to hex string */
void md5_to_string(const uint8_t digest[MD5_DIGEST_LENGTH], char *str);

/* Compare MD5 hex string with digest, returns 0 if match */
int md5_compare(const char *hex_str, const uint8_t digest[MD5_DIGEST_LENGTH]);

#endif
