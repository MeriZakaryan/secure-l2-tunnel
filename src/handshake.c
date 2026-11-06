#include "handshake.h"

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#define HS_HDR_LEN  (14 + 4)        // Ethernet header + 'S' 'L' + version + type
#define HELLO_LEN   (HS_HDR_LEN + HS_NONCE_LEN + HS_DH_PUB_LEN)
#define REPLY_LEN   (HS_HDR_LEN + HS_NONCE_LEN + HS_DH_PUB_LEN + HS_SIG_LEN)
#define FINISH_LEN  (HS_HDR_LEN + HS_SIG_LEN)
#define HS_VERSION  1
#define DH_GROUP    "ffdhe2048"

// Labels separate the different uses of hashes and signatures ("domain separation")
static const char LABEL_TRANSCRIPT[] = "SL2T-v1 transcript";
static const char LABEL_SIG_RESP[]   = "SL2T-v1 responder signature";
static const char LABEL_SIG_INIT[]   = "SL2T-v1 initiator signature";
static const char LABEL_HKDF[]       = "SL2T-v1 session keys";
#define LBL(x) (x), (sizeof(x) - 1)   // label pointer + length without the final '\0'

// ======================= Building blocks =======================

static EVP_PKEY *load_key(const char *path, int is_private) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }
    EVP_PKEY *k = is_private ? PEM_read_PrivateKey(f, NULL, NULL, NULL)
                             : PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) fprintf(stderr, "Cannot parse key file %s\n", path);
    return k;
}

// New ephemeral DH key pair: random private x, public value g^x mod p (256 bytes, padded)
static int dh_generate(EVP_PKEY **out, uint8_t pub[HS_DH_PUB_LEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    BIGNUM *bn = NULL;
    int ok = 0;
    *out = NULL;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_group_name(ctx, DH_GROUP) <= 0) goto done;   // standard p and g
    if (EVP_PKEY_generate(ctx, out) <= 0) goto done;
    if (EVP_PKEY_get_bn_param(*out, OSSL_PKEY_PARAM_PUB_KEY, &bn) != 1) goto done;
    if (BN_bn2binpad(bn, pub, HS_DH_PUB_LEN) != HS_DH_PUB_LEN) goto done;
    ok = 1;
done:
    BN_free(bn);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) { EVP_PKEY_free(*out); *out = NULL; }
    return ok ? 0 : -1;
}

// Wrap the peer's raw public value into an EVP_PKEY of the same group
static EVP_PKEY *dh_peer_key(const uint8_t pub[HS_DH_PUB_LEN]) {
    EVP_PKEY *peer = NULL;
    BIGNUM *bn = BN_bin2bn(pub, HS_DH_PUB_LEN, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

    if (!bn || !bld || !ctx) goto done;
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, DH_GROUP, 0)) goto done;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bn)) goto done;
    if (!(params = OSSL_PARAM_BLD_to_param(bld))) goto done;
    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0) peer = NULL;
done:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn);
    EVP_PKEY_CTX_free(ctx);
    return peer;
}

// Shared secret = peer_pub ^ my_private mod p, always exactly 256 bytes
static int dh_derive(EVP_PKEY *mine, const uint8_t peer_pub[HS_DH_PUB_LEN],
                     uint8_t secret[HS_DH_PUB_LEN]) {
    EVP_PKEY *peer = dh_peer_key(peer_pub);
    EVP_PKEY_CTX *chk = NULL, *ctx = NULL;
    size_t len = HS_DH_PUB_LEN;
    int ok = 0;
    if (!peer) goto done;

    // Reject weak public values (0, 1, p-1, values outside the prime-order subgroup)
    chk = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL);
    if (!chk || EVP_PKEY_public_check(chk) != 1) {
        fprintf(stderr, "[HS] invalid DH public value from peer\n");
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, mine, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_dh_pad(ctx, 1) <= 0) goto done;      // fixed length, no leading-zero leak
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto done;
    if (EVP_PKEY_derive(ctx, secret, &len) <= 0 || len != HS_DH_PUB_LEN) goto done;
    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(chk);
    EVP_PKEY_free(peer);
    return ok ? 0 : -1;
}

// RSA-PSS signature with SHA-256
static int rsa_sign(EVP_PKEY *key, const uint8_t *msg, size_t len, uint8_t sig[HS_SIG_LEN]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    size_t sig_len = HS_SIG_LEN;
    int ok = 0;
    if (!md) return -1;
    if (EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, key) != 1) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) goto done;
    if (EVP_DigestSign(md, sig, &sig_len, msg, len) != 1 || sig_len != HS_SIG_LEN) goto done;
    ok = 1;
done:
    EVP_MD_CTX_free(md);
    return ok ? 0 : -1;
}

static int rsa_verify(EVP_PKEY *key, const uint8_t *msg, size_t len, const uint8_t *sig) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;
    if (!md) return -1;
    if (EVP_DigestVerifyInit(md, &pctx, EVP_sha256(), NULL, key) != 1) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) goto done;
    ok = (EVP_DigestVerify(md, sig, HS_SIG_LEN, msg, len) == 1);
done:
    EVP_MD_CTX_free(md);
    return ok ? 0 : -1;
}

// H = SHA-256(label | nonce1 | pub1 | nonce2 | pub2)
static int compute_transcript(struct hs_state *s) {
    uint8_t buf[sizeof(LABEL_TRANSCRIPT) - 1 + 2 * (HS_NONCE_LEN + HS_DH_PUB_LEN)];
    uint8_t *p = buf;
    memcpy(p, LBL(LABEL_TRANSCRIPT));  p += sizeof(LABEL_TRANSCRIPT) - 1;
    memcpy(p, s->nonce1, HS_NONCE_LEN); p += HS_NONCE_LEN;
    memcpy(p, s->pub1, HS_DH_PUB_LEN);  p += HS_DH_PUB_LEN;
    memcpy(p, s->nonce2, HS_NONCE_LEN); p += HS_NONCE_LEN;
    memcpy(p, s->pub2, HS_DH_PUB_LEN);
    unsigned int hl = 0;
    if (EVP_Digest(buf, sizeof(buf), s->th, &hl, EVP_sha256(), NULL) != 1 || hl != HS_HASH_LEN)
        return -1;
    return 0;
}

// What gets signed: role label | transcript hash
static size_t sig_input(const struct hs_state *s, const char *label, size_t label_len, uint8_t *out) {
    memcpy(out, label, label_len);
    memcpy(out + label_len, s->th, HS_HASH_LEN);
    return label_len + HS_HASH_LEN;
}

// HKDF-SHA256: secret -> two AES keys + two salts (one per direction)
static int hkdf_keys(const uint8_t *secret, size_t slen, const uint8_t th[HS_HASH_LEN],
                     struct hs_keys *k) {
    uint8_t okm[2 * AES_KEY_LEN + 2 * SALT_LEN];
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    OSSL_PARAM params[5], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret, slen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)th, HS_HASH_LEN);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)LABEL_HKDF,
                                             sizeof(LABEL_HKDF) - 1);
    *p   = OSSL_PARAM_construct_end();

    int ok = kctx && EVP_KDF_derive(kctx, okm, sizeof(okm), params) == 1;
    if (ok) {
        memcpy(k->k12, okm, AES_KEY_LEN);
        memcpy(k->k21, okm + AES_KEY_LEN, AES_KEY_LEN);
        memcpy(k->s12, okm + 2 * AES_KEY_LEN, SALT_LEN);
        memcpy(k->s21, okm + 2 * AES_KEY_LEN + SALT_LEN, SALT_LEN);
    }
    OPENSSL_cleanse(okm, sizeof(okm));
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok ? 0 : -1;
}

// DH secret -> session keys, then destroy the ephemeral private key (forward secrecy)
static int derive_session(struct hs_state *s, const uint8_t *peer_pub, struct hs_keys *keys) {
    uint8_t secret[HS_DH_PUB_LEN];
    int ok = dh_derive(s->dh, peer_pub, secret) == 0 &&
             hkdf_keys(secret, sizeof(secret), s->th, keys) == 0;
    OPENSSL_cleanse(secret, sizeof(secret));
    EVP_PKEY_free(s->dh);
    s->dh = NULL;
    s->done = ok;
    return ok ? 0 : -1;
}

static size_t frame_header(const struct hs_state *s, uint8_t *f, uint8_t type) {
    memset(f, 0xff, 6);                  // destination: broadcast (peer MAC unknown)
    memcpy(f + 6, s->mac, 6);            // source: our WAN interface
    f[12] = HS_ETHERTYPE >> 8;
    f[13] = HS_ETHERTYPE & 0xff;
    f[14] = 'S'; f[15] = 'L';            // magic
    f[16] = HS_VERSION;
    f[17] = type;
    return HS_HDR_LEN;
}

// ======================= Public functions =======================

int hs_init(struct hs_state *s, int role, const char *my_priv_pem,
            const char *peer_pub_pem, const uint8_t mac[6]) {
    memset(s, 0, sizeof(*s));
    s->role = role;
    memcpy(s->mac, mac, 6);
    s->my_key = load_key(my_priv_pem, 1);
    s->peer_key = load_key(peer_pub_pem, 0);
    if (!s->my_key || !s->peer_key) return -1;
    if (!EVP_PKEY_is_a(s->my_key, "RSA") || !EVP_PKEY_is_a(s->peer_key, "RSA") ||
        EVP_PKEY_get_size(s->my_key) != HS_SIG_LEN || EVP_PKEY_get_size(s->peer_key) != HS_SIG_LEN) {
        fprintf(stderr, "Keys must be RSA-2048\n");
        return -1;
    }
    return 0;
}

size_t hs_build_hello(struct hs_state *s, uint8_t *f) {
    if (s->role != 1 || s->done) return 0;
    if (!s->dh) {   // first HELLO of this handshake: fresh nonce and ephemeral DH key
        if (RAND_bytes(s->nonce1, HS_NONCE_LEN) != 1 || dh_generate(&s->dh, s->pub1) < 0) {
            fprintf(stderr, "[HS] key generation failed\n");
            return 0;
        }
    }
    uint8_t *p = f + frame_header(s, f, HS_HELLO);
    memcpy(p, s->nonce1, HS_NONCE_LEN);
    memcpy(p + HS_NONCE_LEN, s->pub1, HS_DH_PUB_LEN);
    return HELLO_LEN;
}

int hs_handle(struct hs_state *s, const uint8_t *f, size_t len,
              uint8_t *out, size_t *out_len, struct hs_keys *keys) {
    *out_len = 0;
    if (len < HS_HDR_LEN || f[14] != 'S' || f[15] != 'L' || f[16] != HS_VERSION) return 0;
    uint8_t type = f[17];
    const uint8_t *b = f + HS_HDR_LEN;
    uint8_t msg[64], sig[HS_SIG_LEN];
    size_t msg_len;

    // ---------- Responder (Device2) receives HELLO ----------
    if (s->role == 2 && type == HS_HELLO) {
        if (len != HELLO_LEN) return -1;
        if (memcmp(b, s->nonce1, HS_NONCE_LEN) == 0 && (s->dh || s->done)) {
            if (s->done) return 0;                         // late copy of a finished handshake
            memcpy(out, s->last_reply, s->last_reply_len); // retransmitted HELLO: same REPLY
            *out_len = s->last_reply_len;
            return HS_SEND;
        }
        // New handshake: fresh nonce2 and fresh ephemeral DH key pair
        EVP_PKEY_free(s->dh);
        s->dh = NULL;
        s->done = 0;
        memcpy(s->nonce1, b, HS_NONCE_LEN);
        memcpy(s->pub1, b + HS_NONCE_LEN, HS_DH_PUB_LEN);
        if (RAND_bytes(s->nonce2, HS_NONCE_LEN) != 1 || dh_generate(&s->dh, s->pub2) < 0) return -1;
        if (compute_transcript(s) < 0) return -1;
        msg_len = sig_input(s, LBL(LABEL_SIG_RESP), msg);
        if (rsa_sign(s->my_key, msg, msg_len, sig) < 0) return -1;

        uint8_t *p = out + frame_header(s, out, HS_REPLY);
        memcpy(p, s->nonce2, HS_NONCE_LEN);  p += HS_NONCE_LEN;
        memcpy(p, s->pub2, HS_DH_PUB_LEN);   p += HS_DH_PUB_LEN;
        memcpy(p, sig, HS_SIG_LEN);
        *out_len = REPLY_LEN;
        memcpy(s->last_reply, out, REPLY_LEN);
        s->last_reply_len = REPLY_LEN;
        printf("[HS] HELLO received -> fresh DH key, signed REPLY sent\n");
        return HS_SEND;
    }

    // ---------- Initiator (Device1) receives REPLY ----------
    if (s->role == 1 && type == HS_REPLY) {
        if (s->done || !s->dh) return 0;                   // nothing pending (e.g. duplicate)
        if (len != REPLY_LEN) return -1;
        memcpy(s->nonce2, b, HS_NONCE_LEN);
        memcpy(s->pub2, b + HS_NONCE_LEN, HS_DH_PUB_LEN);
        if (compute_transcript(s) < 0) return -1;
        msg_len = sig_input(s, LBL(LABEL_SIG_RESP), msg);
        if (rsa_verify(s->peer_key, msg, msg_len, b + HS_NONCE_LEN + HS_DH_PUB_LEN) < 0) {
            fprintf(stderr, "[HS] REPLY signature INVALID: possible MITM, reply ignored\n");
            return -1;
        }
        printf("[HS] REPLY signature valid: Device2 authenticated\n");
        if (derive_session(s, s->pub2, keys) < 0) return -1;

        msg_len = sig_input(s, LBL(LABEL_SIG_INIT), msg);
        if (rsa_sign(s->my_key, msg, msg_len, sig) < 0) return -1;
        memcpy(out + frame_header(s, out, HS_FINISH), sig, HS_SIG_LEN);
        *out_len = FINISH_LEN;
        printf("[HS] signed FINISH sent\n");
        return HS_SEND | HS_READY;
    }

    // ---------- Responder (Device2) receives FINISH ----------
    if (s->role == 2 && type == HS_FINISH) {
        if (s->done || !s->dh) return 0;
        if (len != FINISH_LEN) return -1;
        msg_len = sig_input(s, LBL(LABEL_SIG_INIT), msg);
        if (rsa_verify(s->peer_key, msg, msg_len, b) < 0) {
            fprintf(stderr, "[HS] FINISH signature INVALID: possible MITM, ignored\n");
            return -1;
        }
        printf("[HS] FINISH signature valid: Device1 authenticated\n");
        if (derive_session(s, s->pub1, keys) < 0) return -1;
        return HS_READY;
    }
    return 0;   // message not meant for our role
}

void hs_free(struct hs_state *s) {
    EVP_PKEY_free(s->dh);
    EVP_PKEY_free(s->my_key);
    EVP_PKEY_free(s->peer_key);
    OPENSSL_cleanse(s, sizeof(*s));
}