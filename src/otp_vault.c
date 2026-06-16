/*
 * otp_vault.c - PQOTP vault model + in-memory authenticated encryption.
 *
 * File format (all integers little-endian) - identical envelope to PQPMan,
 * only the magic and the serialized payload differ:
 *
 *   off  size  field
 *   ---  ----  -------------------------------------------------------------
 *   0    8     magic  "PQOTP\0\0\0"
 *   8    1     format_version (1 = password-only, 2 = hybrid KEM)
 *   9    1     cipher_id (1 AES-256-GCM, 2 XChaCha20-Poly1305)
 *   10   1     kdf_id (1 = Argon2id)
 *   11   1     kdf_level (informational)
 *   12   4     argon2 t_cost
 *   16   4     argon2 m_cost (KiB)
 *   20   4     argon2 parallelism
 *   24   16    salt
 *   40   H     hybrid block (only when format_version == 2)
 *   ..   N     base nonce
 *   ..   4     uint32 ciphertext length
 *   ..   *     AEAD ciphertext + tag of the serialized vault
 *
 * Serialized vault plaintext:
 *   "POTV" magic (4) | uint32 version | uint32 n_entries |
 *   per entry:
 *     [u32 len][issuer] [u32 len][account] [u32 len][secret bytes]
 *     u8 algo | u8 digits | u16 period
 *
 * The hybrid block mirrors Ciphers/PQPMan exactly.
 */
#include "otp_vault.h"
#include "hybrid_kem.h"

#include <sodium.h>
#include <argon2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define MAGIC            "PQOTP\0\0\0"
#define MAGIC_LEN        8
#define FMT_PASSWORD     1
#define FMT_HYBRID       2
#define KDF_ID_ARGON2ID  1
#define SALT_LEN         16
#define HEADER_LEN       40
#define MAX_NONCE_LEN    24
#define MAX_TAG_LEN      16

#define PLAIN_MAGIC      "POTV"
#define PLAIN_MAGIC_LEN  4
#define PLAIN_VERSION    1

#define MAX_VAULT_BYTES  (8u * 1024u * 1024u)    /* 8 MiB serialized */
#define MAX_ENTRIES      100000u
#define MAX_NAME_LEN     1024u                    /* issuer / account cap */

#define MAX_KDF_M_COST   (4u * 1024u * 1024u)
#define MAX_KDF_T_COST   16u
#define MAX_KDF_PARALLEL 16u

#define WRAP_KEY_LEN   crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define WRAP_NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define WRAP_ABYTES    crypto_aead_xchacha20poly1305_ietf_ABYTES
#define WRAPPED_SK_LEN (HK_SK_LEN + WRAP_ABYTES)
#define HYBRID_BLOCK_LEN (WRAP_NONCE_LEN + WRAPPED_SK_LEN + HK_KEM_CT_LEN)
#define WRAP_AD     ((const unsigned char *)"PQOTP-HYBRID-WRAP")
#define WRAP_AD_LEN 17

/* ----- vault container -------------------------------------------------- */

struct otp_vault {
    vault_cipher_t cipher;
    vault_kdf_t    kdf;
    int            hybrid;
    otp_entry_t   *entries;
    size_t         count;
    size_t         cap;
};

typedef struct { uint32_t t_cost, m_cost, parallelism; } kdf_params_t;

/* ----- small helpers ---------------------------------------------------- */

static void seterr(char *err, size_t n, const char *m) {
    if (err && n) snprintf(err, n, "%s", m);
}
static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static char *dup_field(const char *s) {
    if (!s) s = "";
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}
static void wipe_free(char *s) {
    if (!s) return;
    sodium_memzero(s, strlen(s));
    free(s);
}
static void entry_wipe(otp_entry_t *e) {
    wipe_free(e->issuer);
    wipe_free(e->account);
    sodium_memzero(e->secret, sizeof(e->secret));
    memset(e, 0, sizeof(*e));
}

static void kdf_params_for(vault_kdf_t lvl, kdf_params_t *p) {
    switch (lvl) {
    case VAULT_KDF_BASIC:
        p->t_cost = 3; p->m_cost = 256u * 1024u;       p->parallelism = 4; break;
    case VAULT_KDF_STRONG:
        p->t_cost = 4; p->m_cost = 4u * 1024u * 1024u; p->parallelism = 8; break;
    case VAULT_KDF_MEDIUM:
    default:
        p->t_cost = 3; p->m_cost = 1u * 1024u * 1024u; p->parallelism = 4; break;
    }
}
static int derive_key(const char *pw, const uint8_t *salt,
                      const kdf_params_t *p, uint8_t *key, size_t key_len) {
    return argon2id_hash_raw(p->t_cost, p->m_cost, p->parallelism,
                             pw, strlen(pw), salt, SALT_LEN, key, key_len)
           == ARGON2_OK ? 0 : -1;
}

/* ----- AEAD glue (identical to PQPMan) ---------------------------------- */

typedef int (*aead_enc)(unsigned char *, unsigned long long *,
                        const unsigned char *, unsigned long long,
                        const unsigned char *, unsigned long long,
                        const unsigned char *, const unsigned char *);
typedef int (*aead_dec)(unsigned char *, unsigned long long *,
                        const unsigned char *, unsigned long long,
                        const unsigned char *, unsigned long long,
                        const unsigned char *, const unsigned char *);

static int aes_e(unsigned char *c, unsigned long long *cl, const unsigned char *m,
                 unsigned long long ml, const unsigned char *a, unsigned long long al,
                 const unsigned char *n, const unsigned char *k) {
    return crypto_aead_aes256gcm_encrypt(c, cl, m, ml, a, al, NULL, n, k);
}
static int aes_d(unsigned char *m, unsigned long long *ml, const unsigned char *c,
                 unsigned long long cl, const unsigned char *a, unsigned long long al,
                 const unsigned char *n, const unsigned char *k) {
    return crypto_aead_aes256gcm_decrypt(m, ml, NULL, c, cl, a, al, n, k);
}
static int xc_e(unsigned char *c, unsigned long long *cl, const unsigned char *m,
                unsigned long long ml, const unsigned char *a, unsigned long long al,
                const unsigned char *n, const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_encrypt(c, cl, m, ml, a, al, NULL, n, k);
}
static int xc_d(unsigned char *m, unsigned long long *ml, const unsigned char *c,
                unsigned long long cl, const unsigned char *a, unsigned long long al,
                const unsigned char *n, const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(m, ml, NULL, c, cl, a, al, n, k);
}
static int cipher_geom(vault_cipher_t id, size_t *key_len, size_t *nonce_len,
                       size_t *tag_len, aead_enc *enc, aead_dec *dec) {
    switch (id) {
    case VAULT_CIPHER_AES_256_GCM:
        *key_len = crypto_aead_aes256gcm_KEYBYTES;
        *nonce_len = crypto_aead_aes256gcm_NPUBBYTES;
        *tag_len = crypto_aead_aes256gcm_ABYTES;
        *enc = aes_e; *dec = aes_d; return 0;
    case VAULT_CIPHER_XCHACHA20_POLY1305:
        *key_len = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
        *nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        *tag_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;
        *enc = xc_e; *dec = xc_d; return 0;
    default: return -1;
    }
}
static int cipher_available(vault_cipher_t id) {
    if (id == VAULT_CIPHER_AES_256_GCM)
        return crypto_aead_aes256gcm_is_available() ? 1 : 0;
    return id == VAULT_CIPHER_XCHACHA20_POLY1305;
}

/* ----- hybrid block (identical to PQPMan) ------------------------------- */

static int hybrid_build(const char *pw, const uint8_t *salt, const kdf_params_t *kp,
                        uint8_t block[HYBRID_BLOCK_LEN], uint8_t file_key[32]) {
    uint8_t master[WRAP_KEY_LEN];
    uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES], x448_pk[HK_X448_PUBKEY_LEN];
    uint8_t sk[HK_SK_LEN];
    int ret = -1;
    sodium_mlock(master, sizeof(master));
    sodium_mlock(sk, sizeof(sk));
    if (derive_key(pw, salt, kp, master, sizeof(master)) != 0) goto out;
    if (hk_generate_keypair(kyber_pk, sk, x448_pk, sk + HK_KYBER_SECRETKEYBYTES) != 0)
        goto out;
    uint8_t *wrap_nonce = block;
    uint8_t *wrapped_sk = wrap_nonce + WRAP_NONCE_LEN;
    uint8_t *kem_ct     = wrapped_sk + WRAPPED_SK_LEN;
    randombytes_buf(wrap_nonce, WRAP_NONCE_LEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(wrapped_sk, NULL, sk, HK_SK_LEN,
        WRAP_AD, WRAP_AD_LEN, NULL, wrap_nonce, master);
    if (hk_encapsulate(file_key, kem_ct, kyber_pk, x448_pk) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof(master));
    sodium_munlock(sk, sizeof(sk));
    return ret;
}
static int hybrid_open(const char *pw, const uint8_t *salt, const kdf_params_t *kp,
                       const uint8_t block[HYBRID_BLOCK_LEN], uint8_t file_key[32]) {
    uint8_t master[WRAP_KEY_LEN];
    uint8_t sk[HK_SK_LEN];
    int ret = -1;
    sodium_mlock(master, sizeof(master));
    sodium_mlock(sk, sizeof(sk));
    const uint8_t *wrap_nonce = block;
    const uint8_t *wrapped_sk = wrap_nonce + WRAP_NONCE_LEN;
    const uint8_t *kem_ct     = wrapped_sk + WRAPPED_SK_LEN;
    if (derive_key(pw, salt, kp, master, sizeof(master)) != 0) goto out;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(sk, NULL, NULL,
            wrapped_sk, WRAPPED_SK_LEN, WRAP_AD, WRAP_AD_LEN, wrap_nonce, master) != 0)
        goto out;
    if (hk_decapsulate(file_key, kem_ct, sk, sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof(master));
    sodium_munlock(sk, sizeof(sk));
    return ret;
}

/* ----- (de)serialization ------------------------------------------------ */

static size_t serialized_size(const otp_vault_t *v) {
    size_t n = PLAIN_MAGIC_LEN + 4 + 4;
    for (size_t i = 0; i < v->count; i++) {
        const otp_entry_t *e = &v->entries[i];
        n += 4 + strlen(e->issuer);
        n += 4 + strlen(e->account);
        n += 4 + e->secret_len;
        n += 1 + 1 + 2;   /* algo, digits, period(u16) */
        if (n > MAX_VAULT_BYTES) return 0;
    }
    return n;
}

static void serialize(const otp_vault_t *v, uint8_t *buf) {
    uint8_t *p = buf;
    memcpy(p, PLAIN_MAGIC, PLAIN_MAGIC_LEN); p += PLAIN_MAGIC_LEN;
    put_u32(p, PLAIN_VERSION); p += 4;
    put_u32(p, (uint32_t)v->count); p += 4;
    for (size_t i = 0; i < v->count; i++) {
        const otp_entry_t *e = &v->entries[i];
        uint32_t il = (uint32_t)strlen(e->issuer);
        uint32_t al = (uint32_t)strlen(e->account);
        uint32_t sl = (uint32_t)e->secret_len;
        put_u32(p, il); p += 4; memcpy(p, e->issuer, il);  p += il;
        put_u32(p, al); p += 4; memcpy(p, e->account, al); p += al;
        put_u32(p, sl); p += 4; memcpy(p, e->secret, sl);  p += sl;
        *p++ = (uint8_t)e->algo;
        *p++ = (uint8_t)e->digits;
        *p++ = (uint8_t)(e->period & 0xFF);
        *p++ = (uint8_t)((e->period >> 8) & 0xFF);
    }
}

/* Read a length-prefixed field into a freshly malloc'd NUL-terminated string,
 * enforcing max. Advances *pp. Returns the string or NULL on failure. */
static char *read_str(const uint8_t **pp, const uint8_t *end, uint32_t max) {
    const uint8_t *p = *pp;
    if (end - p < 4) return NULL;
    uint32_t l = get_u32(p); p += 4;
    if (l > max || (size_t)(end - p) < l) return NULL;
    char *s = malloc(l + 1);
    if (!s) return NULL;
    memcpy(s, p, l); s[l] = '\0';
    p += l; *pp = p;
    return s;
}

static int deserialize(otp_vault_t *v, const uint8_t *buf, size_t len) {
    if (len < PLAIN_MAGIC_LEN + 8 ||
        memcmp(buf, PLAIN_MAGIC, PLAIN_MAGIC_LEN) != 0) return -1;
    const uint8_t *p = buf + PLAIN_MAGIC_LEN;
    const uint8_t *end = buf + len;
    uint32_t version = get_u32(p); p += 4;
    if (version != PLAIN_VERSION) return -1;
    uint32_t n = get_u32(p); p += 4;
    if (n > MAX_ENTRIES) return -1;

    for (uint32_t i = 0; i < n; i++) {
        char *issuer = read_str(&p, end, MAX_NAME_LEN);
        if (!issuer) return -1;
        char *account = read_str(&p, end, MAX_NAME_LEN);
        if (!account) { wipe_free(issuer); return -1; }

        if (end - p < 4) { wipe_free(issuer); wipe_free(account); return -1; }
        uint32_t sl = get_u32(p); p += 4;
        if (sl > OTP_MAX_SECRET_LEN || (size_t)(end - p) < sl + 4) {
            wipe_free(issuer); wipe_free(account); return -1;
        }
        uint8_t secret[OTP_MAX_SECRET_LEN];
        memcpy(secret, p, sl); p += sl;
        otp_algo_t algo = (otp_algo_t)*p++;
        int digits = *p++;
        int period = (int)p[0] | ((int)p[1] << 8); p += 2;
        if (digits < 6 || digits > 10) digits = 6;
        if (period <= 0 || period > 600) period = 30;

        size_t idx = otp_vault_add(v, issuer, account, secret, sl,
                                   algo, digits, period);
        sodium_memzero(secret, sizeof(secret));
        wipe_free(issuer); wipe_free(account);
        if (idx == (size_t)-1) return -1;
    }
    return 0;
}

/* ----- lifecycle -------------------------------------------------------- */

int otp_vault_init(void) {
    if (sodium_init() < 0) return -1;
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    return 0;
}

otp_vault_t *otp_vault_new(vault_cipher_t cipher, vault_kdf_t kdf, int hybrid) {
    otp_vault_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    v->cipher = cipher; v->kdf = kdf; v->hybrid = hybrid ? 1 : 0;
    return v;
}
void otp_vault_free(otp_vault_t *v) {
    if (!v) return;
    for (size_t i = 0; i < v->count; i++) entry_wipe(&v->entries[i]);
    free(v->entries);
    free(v);
}
vault_cipher_t otp_vault_cipher(const otp_vault_t *v) { return v->cipher; }
vault_kdf_t    otp_vault_kdf(const otp_vault_t *v)    { return v->kdf; }
int            otp_vault_is_hybrid(const otp_vault_t *v) { return v->hybrid; }
size_t         otp_vault_count(const otp_vault_t *v)  { return v->count; }
const otp_entry_t *otp_vault_get(const otp_vault_t *v, size_t i) {
    return i < v->count ? &v->entries[i] : NULL;
}

size_t otp_vault_add(otp_vault_t *v, const char *issuer, const char *account,
                     const uint8_t *secret, size_t secret_len,
                     otp_algo_t algo, int digits, int period) {
    if (secret_len > OTP_MAX_SECRET_LEN) return (size_t)-1;
    if (v->count == v->cap) {
        size_t nc = v->cap ? v->cap * 2 : 8;
        otp_entry_t *ne = realloc(v->entries, nc * sizeof(*ne));
        if (!ne) return (size_t)-1;
        v->entries = ne;
        v->cap = nc;
    }
    otp_entry_t *e = &v->entries[v->count];
    memset(e, 0, sizeof(*e));
    e->issuer = dup_field(issuer);
    e->account = dup_field(account);
    if (!e->issuer || !e->account) { entry_wipe(e); return (size_t)-1; }
    memcpy(e->secret, secret, secret_len);
    e->secret_len = secret_len;
    e->algo = algo;
    e->digits = digits;
    e->period = period;
    return v->count++;
}

int otp_vault_remove(otp_vault_t *v, size_t i) {
    if (i >= v->count) return -1;
    entry_wipe(&v->entries[i]);
    memmove(&v->entries[i], &v->entries[i + 1],
            (v->count - i - 1) * sizeof(v->entries[0]));
    v->count--;
    return 0;
}

/* ----- save / load (envelope identical to PQPMan) ----------------------- */

static void fsync_parent_dir(const char *path) {
    char dir[4096];
    const char *slash = strrchr(path, '/');
    if (slash == path) { dir[0] = '/'; dir[1] = '\0'; }
    else if (slash) {
        size_t n = (size_t)(slash - path);
        if (n >= sizeof(dir)) return;
        memcpy(dir, path, n); dir[n] = '\0';
    } else { dir[0] = '.'; dir[1] = '\0'; }
    int fd = open(dir, O_RDONLY
#ifdef O_DIRECTORY
                  | O_DIRECTORY
#endif
                  );
    if (fd < 0) return;
    fsync(fd);
    close(fd);
}

int otp_vault_save(otp_vault_t *v, const char *path, const char *password,
                   char *err, size_t errlen) {
    if (!password || !*password) { seterr(err, errlen, "A master password is required."); return -1; }
    size_t key_len, nonce_len, tag_len;
    aead_enc enc; aead_dec dec;
    if (cipher_geom(v->cipher, &key_len, &nonce_len, &tag_len, &enc, &dec) != 0) {
        seterr(err, errlen, "Unknown cipher."); return -1;
    }
    if (!cipher_available(v->cipher)) {
        seterr(err, errlen, "Cipher not supported on this CPU (AES-256-GCM needs hardware AES)."); return -1;
    }
    size_t plen = serialized_size(v);
    if (plen == 0) { seterr(err, errlen, "Vault is too large to serialize."); return -1; }

    int ret = -1;
    uint8_t key[32];
    uint8_t salt[SALT_LEN], base_nonce[MAX_NONCE_LEN];
    uint8_t *plain = sodium_malloc(plen);
    uint8_t *ct = malloc(plen + MAX_TAG_LEN);
    uint8_t *hybrid_block = NULL;
    FILE *out = NULL;
    char tmp[4096 + 24];

    sodium_mlock(key, sizeof(key));
    if (!plain || !ct) { seterr(err, errlen, "Out of memory."); goto done; }
    if (snprintf(tmp, sizeof(tmp), "%s.pqotp-tmp", path) >= (int)sizeof(tmp)) {
        seterr(err, errlen, "Output path is too long."); goto done;
    }

    kdf_params_t kp; kdf_params_for(v->kdf, &kp);
    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(base_nonce, nonce_len);

    if (v->hybrid) {
        hybrid_block = malloc(HYBRID_BLOCK_LEN);
        if (!hybrid_block) { seterr(err, errlen, "Out of memory."); goto done; }
        if (hybrid_build(password, salt, &kp, hybrid_block, key) != 0) {
            seterr(err, errlen, "Hybrid key setup failed."); goto done;
        }
    } else if (derive_key(password, salt, &kp, key, key_len) != 0) {
        seterr(err, errlen, "Key derivation failed."); goto done;
    }

    serialize(v, plain);
    unsigned long long clen = 0;
    if (enc(ct, &clen, plain, plen, NULL, 0, base_nonce, key) != 0) {
        seterr(err, errlen, "Encryption failed."); goto done;
    }

    uint8_t hdr[HEADER_LEN];
    memcpy(hdr, MAGIC, MAGIC_LEN);
    hdr[8]  = v->hybrid ? FMT_HYBRID : FMT_PASSWORD;
    hdr[9]  = (uint8_t)v->cipher;
    hdr[10] = KDF_ID_ARGON2ID;
    hdr[11] = (uint8_t)v->kdf;
    put_u32(hdr + 12, kp.t_cost);
    put_u32(hdr + 16, kp.m_cost);
    put_u32(hdr + 20, kp.parallelism);
    memcpy(hdr + 24, salt, SALT_LEN);

    {
        int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) { seterr(err, errlen, "Cannot open output file."); goto done; }
        out = fdopen(fd, "wb");
        if (!out) { close(fd); seterr(err, errlen, "Cannot open output file."); goto done; }
    }

    uint8_t lenbuf[4]; put_u32(lenbuf, (uint32_t)clen);
    if (fwrite(hdr, 1, HEADER_LEN, out) != HEADER_LEN ||
        (v->hybrid && fwrite(hybrid_block, 1, HYBRID_BLOCK_LEN, out) != HYBRID_BLOCK_LEN) ||
        fwrite(base_nonce, 1, nonce_len, out) != nonce_len ||
        fwrite(lenbuf, 1, 4, out) != 4 ||
        fwrite(ct, 1, (size_t)clen, out) != (size_t)clen) {
        seterr(err, errlen, "Write error."); goto done;
    }
    if (fflush(out) != 0 || ferror(out) || fsync(fileno(out)) != 0) {
        seterr(err, errlen, "Write error."); goto done;
    }
    ret = 0;
done:
    sodium_munlock(key, sizeof(key));
    if (plain) sodium_free(plain);
    if (ct) { sodium_memzero(ct, plen + MAX_TAG_LEN); free(ct); }
    free(hybrid_block);
    if (out) {
        fclose(out);
        if (ret == 0 && rename(tmp, path) != 0) {
            seterr(err, errlen, "Could not write output file."); ret = -1;
        }
        if (ret == 0) fsync_parent_dir(path);
        if (ret != 0) remove(tmp);
    }
    return ret;
}

int otp_vault_load(const char *path, const char *password, otp_vault_t **out,
                   char *err, size_t errlen) {
    *out = NULL;
    FILE *in = fopen(path, "rb");
    if (!in) { seterr(err, errlen, "Cannot open vault file."); return -1; }

    int ret = -1;
    uint8_t key[32];
    uint8_t *ct = NULL, *plain = NULL, *hybrid_block = NULL;
    otp_vault_t *v = NULL;
    size_t plen_alloc = 0;
    sodium_mlock(key, sizeof(key));

    uint8_t hdr[HEADER_LEN];
    if (fread(hdr, 1, HEADER_LEN, in) != HEADER_LEN ||
        memcmp(hdr, MAGIC, MAGIC_LEN) != 0) {
        seterr(err, errlen, "Not a PQOTP vault (bad magic)."); goto done;
    }
    int hybrid = (hdr[8] == FMT_HYBRID);
    if (hdr[8] != FMT_PASSWORD && !hybrid) {
        seterr(err, errlen, "Unsupported vault format version."); goto done;
    }
    vault_cipher_t cipher = (vault_cipher_t)hdr[9];
    size_t key_len, nonce_len, tag_len; aead_enc enc; aead_dec dec;
    if (cipher_geom(cipher, &key_len, &nonce_len, &tag_len, &enc, &dec) != 0) {
        seterr(err, errlen, "Unknown cipher in vault."); goto done;
    }
    if (!cipher_available(cipher)) {
        seterr(err, errlen, "Cipher in vault not supported on this CPU."); goto done;
    }
    if (hdr[10] != KDF_ID_ARGON2ID) { seterr(err, errlen, "Unknown KDF in vault."); goto done; }

    kdf_params_t kp;
    kp.t_cost = get_u32(hdr + 12);
    kp.m_cost = get_u32(hdr + 16);
    kp.parallelism = get_u32(hdr + 20);
    if (kp.t_cost == 0 || kp.t_cost > MAX_KDF_T_COST ||
        kp.m_cost < 8u || kp.m_cost > MAX_KDF_M_COST ||
        kp.parallelism == 0 || kp.parallelism > MAX_KDF_PARALLEL) {
        seterr(err, errlen, "Invalid or unsafe KDF parameters in vault."); goto done;
    }

    if (hybrid) {
        hybrid_block = malloc(HYBRID_BLOCK_LEN);
        if (!hybrid_block) { seterr(err, errlen, "Out of memory."); goto done; }
        if (fread(hybrid_block, 1, HYBRID_BLOCK_LEN, in) != HYBRID_BLOCK_LEN) {
            seterr(err, errlen, "Truncated vault header."); goto done;
        }
        if (hybrid_open(password, hdr + 24, &kp, hybrid_block, key) != 0) {
            seterr(err, errlen, "Unlock failed: wrong password or corrupted/tampered vault."); goto done;
        }
    }

    uint8_t base_nonce[MAX_NONCE_LEN];
    if (fread(base_nonce, 1, nonce_len, in) != nonce_len) {
        seterr(err, errlen, "Truncated vault header."); goto done;
    }
    if (!hybrid && derive_key(password, hdr + 24, &kp, key, key_len) != 0) {
        seterr(err, errlen, "Key derivation failed."); goto done;
    }

    uint8_t lenbuf[4];
    if (fread(lenbuf, 1, 4, in) != 4) { seterr(err, errlen, "Truncated vault."); goto done; }
    uint32_t clen = get_u32(lenbuf);
    if (clen < tag_len || clen > MAX_VAULT_BYTES + MAX_TAG_LEN) {
        seterr(err, errlen, "Corrupt vault length."); goto done;
    }
    ct = malloc(clen);
    if (!ct) { seterr(err, errlen, "Out of memory."); goto done; }
    if (fread(ct, 1, clen, in) != clen) { seterr(err, errlen, "Truncated vault."); goto done; }

    plen_alloc = clen;
    plain = sodium_malloc(plen_alloc);
    if (!plain) { seterr(err, errlen, "Out of memory."); goto done; }

    unsigned long long mlen = 0;
    if (dec(plain, &mlen, ct, clen, NULL, 0, base_nonce, key) != 0) {
        seterr(err, errlen, "Unlock failed: wrong password or corrupted/tampered vault."); goto done;
    }

    v = otp_vault_new(cipher, (vault_kdf_t)hdr[11], hybrid);
    if (!v) { seterr(err, errlen, "Out of memory."); goto done; }
    if (deserialize(v, plain, (size_t)mlen) != 0) {
        seterr(err, errlen, "Vault is corrupt (bad contents)."); otp_vault_free(v); v = NULL; goto done;
    }
    *out = v;
    ret = 0;
done:
    sodium_munlock(key, sizeof(key));
    if (plain) sodium_free(plain);
    if (ct) free(ct);
    free(hybrid_block);
    fclose(in);
    return ret;
}
