/*
 * totp.c - HOTP/TOTP computation, base32 decoding and otpauth URI parsing.
 *
 * See totp.h. HMAC comes from OpenSSL's one-shot HMAC(); the dynamic
 * truncation and modulo are exactly as specified in RFC 4226 section 5.
 */
#include "totp.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sodium.h>

const char *otp_algo_name(otp_algo_t a) {
    switch (a) {
    case OTP_SHA256: return "SHA256";
    case OTP_SHA512: return "SHA512";
    case OTP_SHA1:
    default:         return "SHA1";
    }
}

static const EVP_MD *md_for(otp_algo_t a) {
    switch (a) {
    case OTP_SHA256: return EVP_sha256();
    case OTP_SHA512: return EVP_sha512();
    case OTP_SHA1:
    default:         return EVP_sha1();
    }
}

/* ----- base32 (RFC 4648) ------------------------------------------------ */

/* Map a base32 alphabet character to its 5-bit value, or -1 if invalid. */
static int b32_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

int otp_base32_decode(const char *in, uint8_t *out, size_t out_cap) {
    if (!in || !out) return -1;
    uint32_t buffer = 0;
    int bits = 0;
    size_t n = 0;

    for (const char *p = in; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == ' ' || c == '\t' || c == '-' || c == '=') continue; /* skip */
        int v = b32_val(c);
        if (v < 0) return -1;
        buffer = (buffer << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_cap) return -1;
            out[n++] = (uint8_t)((buffer >> bits) & 0xFF);
        }
    }
    return (int)n;
}

/* ----- HOTP / TOTP ------------------------------------------------------ */

int otp_hotp(const uint8_t *secret, size_t secret_len, otp_algo_t algo,
             uint64_t counter, int digits, uint32_t *out_code) {
    if (!secret || !out_code || digits < 6 || digits > 10) return -1;

    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) { msg[i] = (uint8_t)(counter & 0xFF); counter >>= 8; }

    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (!HMAC(md_for(algo), secret, (int)secret_len, msg, sizeof(msg),
              mac, &mac_len) || mac_len < 20) {
        sodium_memzero(mac, sizeof(mac));
        return -1;
    }

    int offset = mac[mac_len - 1] & 0x0F;
    uint32_t bin = ((uint32_t)(mac[offset]     & 0x7F) << 24) |
                   ((uint32_t)(mac[offset + 1] & 0xFF) << 16) |
                   ((uint32_t)(mac[offset + 2] & 0xFF) <<  8) |
                   ((uint32_t)(mac[offset + 3] & 0xFF));
    sodium_memzero(mac, sizeof(mac));

    static const uint32_t pow10[] = {
        1, 10, 100, 1000, 10000, 100000, 1000000, 10000000,
        100000000, 1000000000
    };
    *out_code = bin % pow10[digits];
    return 0;
}

int otp_totp(const uint8_t *secret, size_t secret_len, otp_algo_t algo,
             time_t when, int period, int digits,
             char *buf, size_t buf_cap, int *remaining) {
    if (period <= 0 || !buf || (size_t)digits + 1 > buf_cap) return -1;
    uint64_t counter = (uint64_t)(when / period);
    uint32_t code = 0;
    if (otp_hotp(secret, secret_len, algo, counter, digits, &code) != 0) return -1;
    snprintf(buf, buf_cap, "%0*u", digits, code);
    if (remaining) *remaining = period - (int)(when % period);
    return 0;
}

/* ----- otpauth:// URI parsing ------------------------------------------- */

/* In-place percent-decode of a URI component. */
static void percent_decode(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '%' && isxdigit((unsigned char)r[1]) && isxdigit((unsigned char)r[2])) {
            char h[3] = { r[1], r[2], 0 };
            *w++ = (char)strtol(h, NULL, 16);
            r += 2;
        } else if (*r == '+') {
            *w++ = ' ';
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
}

int otp_parse_uri(const char *uri,
                  char *issuer, char *account,
                  uint8_t *secret, size_t *secret_len,
                  otp_algo_t *algo, int *digits, int *period) {
    if (!uri || !issuer || !account || !secret || !secret_len ||
        !algo || !digits || !period) return -1;

    /* Defaults per the de-facto otpauth spec. */
    issuer[0] = '\0';
    account[0] = '\0';
    *algo = OTP_SHA1;
    *digits = 6;
    *period = 30;
    *secret_len = 0;

    const char *p;
    if (strncmp(uri, "otpauth://totp/", 15) == 0)      p = uri + 15;
    else if (strncmp(uri, "otpauth://hotp/", 15) == 0) p = uri + 15;
    else return -1;

    /* Work on a private copy: label up to '?', then query. */
    char *copy = strdup(p);
    if (!copy) return -1;
    int ret = -1;
    int have_secret = 0;

    char *query = strchr(copy, '?');
    if (query) *query++ = '\0';

    /* Label: "Issuer:Account" or just "Account". */
    {
        char label[256];
        snprintf(label, sizeof(label), "%s", copy);
        percent_decode(label);
        char *colon = strchr(label, ':');
        if (colon) {
            *colon = '\0';
            snprintf(issuer, 256, "%s", label);
            const char *acc = colon + 1;
            while (*acc == ' ') acc++;
            snprintf(account, 256, "%s", acc);
        } else {
            snprintf(account, 256, "%s", label);
        }
    }

    for (char *kv = query; kv && *kv; ) {
        char *amp = strchr(kv, '&');
        if (amp) *amp = '\0';
        char *eq = strchr(kv, '=');
        if (eq) {
            *eq = '\0';
            char *key = kv, *val = eq + 1;
            percent_decode(val);
            if (strcmp(key, "secret") == 0) {
                int n = otp_base32_decode(val, secret, OTP_MAX_SECRET_LEN);
                if (n > 0) { *secret_len = (size_t)n; have_secret = 1; }
            } else if (strcmp(key, "issuer") == 0) {
                if (issuer[0] == '\0') snprintf(issuer, 256, "%s", val);
            } else if (strcmp(key, "algorithm") == 0) {
                if (strcasecmp(val, "SHA256") == 0) *algo = OTP_SHA256;
                else if (strcasecmp(val, "SHA512") == 0) *algo = OTP_SHA512;
                else *algo = OTP_SHA1;
            } else if (strcmp(key, "digits") == 0) {
                int d = atoi(val);
                if (d >= 6 && d <= 10) *digits = d;
            } else if (strcmp(key, "period") == 0) {
                int per = atoi(val);
                if (per > 0 && per <= 600) *period = per;
            }
        }
        if (!amp) break;
        kv = amp + 1;
    }

    if (have_secret) ret = 0;
    free(copy);
    return ret;
}
