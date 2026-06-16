/*
 * totp.h - RFC 4226 (HOTP) / RFC 6238 (TOTP) one-time passwords.
 *
 * Pure computation: no I/O, no secrets persisted here. The shared secret is
 * passed in as raw bytes (already base32-decoded) and the caller owns wiping
 * it. HMAC is provided by OpenSSL; SHA-1, SHA-256 and SHA-512 are supported
 * as the OTP hash, matching the otpauth:// ecosystem (Google Authenticator,
 * Authy, ...).
 */
#ifndef PQOTP_TOTP_H
#define PQOTP_TOTP_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* OTP hash algorithm (the HMAC underneath). */
typedef enum {
    OTP_SHA1   = 0,   /* default in practice */
    OTP_SHA256 = 1,
    OTP_SHA512 = 2,
} otp_algo_t;

/* Maximum raw secret we accept (a 512-bit HMAC key is already generous). */
#define OTP_MAX_SECRET_LEN 64

/* Decode a base32 (RFC 4648, no padding required, case-insensitive, spaces
 * ignored) string into out (capacity out_cap). On success returns the number
 * of bytes written; on invalid input or overflow returns -1. */
int otp_base32_decode(const char *in, uint8_t *out, size_t out_cap);

/* Compute an HOTP value (RFC 4226) for the given counter. Returns the integer
 * code in [0, 10^digits) via *out_code, or -1 on error. digits in [6,10]. */
int otp_hotp(const uint8_t *secret, size_t secret_len, otp_algo_t algo,
             uint64_t counter, int digits, uint32_t *out_code);

/* Compute a TOTP value (RFC 6238) at unix time `when`, with step `period`
 * seconds and epoch t0 = 0. Formats the zero-padded code into buf (capacity
 * buf_cap, needs digits+1). Also reports seconds remaining in the current
 * step via *remaining (may be NULL). Returns 0 on success, -1 on error. */
int otp_totp(const uint8_t *secret, size_t secret_len, otp_algo_t algo,
             time_t when, int period, int digits,
             char *buf, size_t buf_cap, int *remaining);

/* Parse an otpauth://totp/... (or hotp) URI. On success fills the caller's
 * buffers (issuer/account capacity >= 256), decodes the secret into secret
 * (capacity OTP_MAX_SECRET_LEN, *secret_len set), and sets algo/digits/period.
 * Returns 0 on success, -1 on malformed input. */
int otp_parse_uri(const char *uri,
                  char *issuer, char *account,
                  uint8_t *secret, size_t *secret_len,
                  otp_algo_t *algo, int *digits, int *period);

/* Human-readable algorithm name ("SHA1"/"SHA256"/"SHA512"). */
const char *otp_algo_name(otp_algo_t a);

#endif /* PQOTP_TOTP_H */
