/*
 * otp_vault.h - PQOTP encrypted store of TOTP/HOTP secrets.
 *
 * Same on-disk security model as PQPMan: the serialized vault is a single
 * AEAD blob (AES-256-GCM or XChaCha20-Poly1305) whose key is protected by the
 * master password through Argon2id and, in hybrid mode, wrapped in a
 * Kyber-1024 + X448 post-quantum KEM layer. A single master password unlocks
 * every OTP secret, and nothing decrypted is ever written to disk.
 *
 * The difference from PQPMan is the entry shape: instead of website
 * credentials, each entry is an OTP account (issuer + account name) plus the
 * raw HMAC secret and its OTP parameters (algorithm, digits, period).
 */
#ifndef PQOTP_VAULT_H
#define PQOTP_VAULT_H

#include <stddef.h>
#include <stdint.h>

#include "totp.h"

typedef enum {
    VAULT_CIPHER_AES_256_GCM        = 1,
    VAULT_CIPHER_XCHACHA20_POLY1305 = 2,
} vault_cipher_t;

typedef enum {
    VAULT_KDF_BASIC  = 0,   /* 256 MiB */
    VAULT_KDF_MEDIUM = 1,   /* 1 GiB  - recommended minimum */
    VAULT_KDF_STRONG = 2,   /* 4 GiB  */
} vault_kdf_t;

/* One OTP account. issuer/account are owned NUL-terminated UTF-8; secret is a
 * raw HMAC key of secret_len bytes (wiped before free). */
typedef struct {
    char       *issuer;     /* e.g. "GitHub" (may be "")            */
    char       *account;    /* e.g. "alice@example.com"             */
    uint8_t     secret[OTP_MAX_SECRET_LEN];
    size_t      secret_len;
    otp_algo_t  algo;
    int         digits;
    int         period;
} otp_entry_t;

typedef struct otp_vault otp_vault_t;

/* Initialise libsodium + process hardening (no core dumps). Call once. */
int otp_vault_init(void);

otp_vault_t *otp_vault_new(vault_cipher_t cipher, vault_kdf_t kdf, int hybrid);
void         otp_vault_free(otp_vault_t *v);

vault_cipher_t otp_vault_cipher(const otp_vault_t *v);
vault_kdf_t    otp_vault_kdf(const otp_vault_t *v);
int            otp_vault_is_hybrid(const otp_vault_t *v);

size_t             otp_vault_count(const otp_vault_t *v);
const otp_entry_t *otp_vault_get(const otp_vault_t *v, size_t index);

/* Add an entry (fields copied). Returns the new index or (size_t)-1. */
size_t otp_vault_add(otp_vault_t *v, const char *issuer, const char *account,
                     const uint8_t *secret, size_t secret_len,
                     otp_algo_t algo, int digits, int period);

int otp_vault_remove(otp_vault_t *v, size_t index);

/* Encrypt+write the vault to path (temp file + rename). 0 on success. */
int otp_vault_save(otp_vault_t *v, const char *path, const char *password,
                   char *err, size_t errlen);

/* Decrypt path into a fresh vault (*out). 0 on success. */
int otp_vault_load(const char *path, const char *password, otp_vault_t **out,
                   char *err, size_t errlen);

#endif /* PQOTP_VAULT_H */
