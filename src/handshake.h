#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include "crypto.h"

#define HS_ETHERTYPE  0x88B5   // IEEE "local experimental" EtherType
#define HS_NONCE_LEN  32
#define HS_DH_PUB_LEN 256      // ffdhe2048: 2048-bit public value
#define HS_SIG_LEN    256      // RSA-2048 signature
#define HS_HASH_LEN   32       // SHA-256
#define HS_MAX_FRAME  600

// hs_handle() result flags
#define HS_SEND  1   // a reply frame was written to 'out': send it
#define HS_READY 2   // session keys were derived into 'keys'

enum { HS_HELLO = 1, HS_REPLY = 2, HS_FINISH = 3 };

struct hs_keys {
    uint8_t k12[AES_KEY_LEN], k21[AES_KEY_LEN];   // Device1->Device2, Device2->Device1
    uint8_t s12[SALT_LEN],    s21[SALT_LEN];
};

struct hs_state {
    int role;                         // 1 = initiator (Device1), 2 = responder (Device2)
    uint8_t mac[6];                   // own WAN MAC: source address of handshake frames
    EVP_PKEY *my_key;                 // long-term RSA private key (signing)
    EVP_PKEY *peer_key;               // long-term RSA public key of the peer (verifying)
    EVP_PKEY *dh;                     // ephemeral DH key pair, destroyed after key derivation
    int done;                         // handshake completed for the current nonce1
    uint8_t nonce1[HS_NONCE_LEN], pub1[HS_DH_PUB_LEN];   // from the initiator
    uint8_t nonce2[HS_NONCE_LEN], pub2[HS_DH_PUB_LEN];   // from the responder
    uint8_t th[HS_HASH_LEN];          // transcript hash over both nonces and DH values
    uint8_t last_reply[HS_MAX_FRAME]; // responder: REPLY kept to answer duplicate HELLOs
    size_t  last_reply_len;
};

// Load the long-term keys. Returns 0 on success, -1 on error.
int    hs_init(struct hs_state *s, int role, const char *my_priv_pem,
               const char *peer_pub_pem, const uint8_t mac[6]);

// Initiator: build a HELLO frame (same values on every retransmission). Returns its length, 0 on error.
size_t hs_build_hello(struct hs_state *s, uint8_t *frame);

// Process a received handshake frame. Returns a combination of HS_SEND / HS_READY,
// 0 if there is nothing to do, -1 if the message was rejected.
int    hs_handle(struct hs_state *s, const uint8_t *frame, size_t len,
                 uint8_t *out, size_t *out_len, struct hs_keys *keys);

void   hs_free(struct hs_state *s);

#endif