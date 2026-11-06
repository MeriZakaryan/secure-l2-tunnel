#include "crypto.h"

#include <string.h>
#include <openssl/evp.h>

void make_nonce(uint8_t nonce[GCM_NONCE_LEN], const uint8_t salt[SALT_LEN], uint64_t counter) {
    memcpy(nonce, salt, SALT_LEN);
    for (int i = GCM_NONCE_LEN - 1; i >= SALT_LEN; i--) {   // counter in big-endian
        nonce[i] = (uint8_t)counter;
        counter >>= 8;
    }
}

int aead_encrypt(const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t len,
                 uint8_t *ct, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0, out_len;

    // 1. Choose the algorithm, then set the nonce length, then key + nonce
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    // 2. AAD: authenticated but not encrypted (output pointer NULL)
    if (aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &out_len, aad, (int)aad_len) != 1) goto done;

    // 3. Encrypt the payload (CTR mode inside GCM: output length == input length)
    if (EVP_EncryptUpdate(ctx, ct, &out_len, pt, (int)len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct + out_len, &out_len) != 1) goto done;

    // 4. Read the 16-byte tag (GHASH result masked with AES_k(J0))
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int aead_decrypt(const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t len,
                 const uint8_t *tag, uint8_t *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0, out_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &out_len, aad, (int)aad_len) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt, &out_len, ct, (int)len) != 1) goto done;

    // Give OpenSSL the received tag; Final recomputes it and compares (in constant time)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt + out_len, &out_len) != 1) goto done;   // != 1 = tag mismatch
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}