#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AES_KEY_LEN   32   // AES-256
#define SALT_LEN      4    // fixed per direction, part of the nonce
#define GCM_NONCE_LEN 12   // 4-byte salt + 8-byte counter
#define GCM_TAG_LEN   16

// nonce = salt (4 bytes) || counter (8 bytes, big-endian)
void make_nonce(uint8_t nonce[GCM_NONCE_LEN], const uint8_t salt[SALT_LEN], uint64_t counter);

// AES-256-GCM encrypt. ct has the same length as pt. Returns 0 on success, -1 on error.
int aead_encrypt(const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t len,
                 uint8_t *ct, uint8_t *tag);

// AES-256-GCM decrypt + verify. Returns 0 if the tag is valid, -1 otherwise.
// On failure, pt must NOT be used.
int aead_decrypt(const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t len,
                 const uint8_t *tag, uint8_t *pt);

#endif