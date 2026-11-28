/*
 * Independent SHA-256 (FIPS 180-4) exposed with the OpenSSL call shapes that
 * liblp uses. liblp's only libcrypto dependency is SHA-256 for metadata
 * checksums; the differential tests recompute every checksum with Python's
 * hashlib, which polices this implementation. Not derived from OpenSSL or
 * AOSP code.
 */
#ifndef CAIRN_SHA256_SHIM_H
#define CAIRN_SHA256_SHIM_H

/* AOSP main uses clang's availability attribute; gcc host builds need this
 * defined away. The guarded branches are Android-only. */
#if defined(__GNUC__) && !defined(__clang__) && !defined(__ANDROID__)
#define __builtin_available(...) true
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t h[8];
    uint64_t total_len;
    uint8_t block[64];
    size_t block_len;
} SHA256_CTX;

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(uint8_t *out, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *data, size_t len, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_SHA256_SHIM_H */
