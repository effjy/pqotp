<div align="center">

# PQOTP

**Post-quantum TOTP / HOTP authenticator for the command line.**

![C](https://img.shields.io/badge/Language-C-teal?style=flat-square&labelColor=1a1a1a)
![PQ](https://img.shields.io/badge/PQ-8a2be2?style=flat-square)
![CLI](https://img.shields.io/badge/CLI-555?style=flat-square)

</div>

PQOTP is a two-factor (2FA) authenticator that stores your TOTP/HOTP secrets in
a single encrypted vault — the companion to [PQPMan](https://github.com/effjy/pqpman).
Unlike Google Authenticator or Authy, the seed store is sealed with the same
**post-quantum hybrid** crypto core PQPMan uses, and nothing is ever synced to a
cloud you don't control.

- **Codes**: RFC 4226 (HOTP) and RFC 6238 (TOTP), SHA-1 / SHA-256 / SHA-512,
  6–10 digits, configurable period. Verified against the RFC 6238 test vectors.
- **At rest**: the serialized vault is one AEAD blob — **AES-256-GCM** or
  **XChaCha20-Poly1305** — whose key is derived with **Argon2id** and, in hybrid
  mode, wrapped in a **Kyber-1024 + X448** KEM layer. A single master password
  unlocks everything; a wrong password or any tampering fails the AEAD tag.
- **In memory**: master key and OTP secrets live in `mlock`'d, non-dumpable
  memory (core dumps disabled, `PR_SET_DUMPABLE` off); the master password is
  wiped right after key derivation.
- **On disk**: written via temp-file + `fsync` + `rename` (never corrupts an
  existing vault) with `0600` permissions.

The crypto envelope is byte-for-byte the PQPMan/Ciphers design; only the magic
(`PQOTP`) and the per-entry payload (issuer, account, raw HMAC secret, algorithm,
digits, period) differ.

PQOTP ships as both a **GTK3 desktop app** (`pqotp-gui`) and a **CLI** (`pqotp`)
that share the same vault format.

## Build

The CLI needs `libsodium`, `libargon2` and `libcrypto` (OpenSSL); the GUI also
needs `gtk+-3.0`.

```sh
make                  # builds ./pqotp-gui and ./pqotp
sudo make install     # installs both binaries, the icon (all sizes) and the
                      # desktop entry globally so PQOTP appears in the menu/taskbar
sudo make uninstall   # removes everything it installed
```

## Desktop app

Launch **PQOTP** from your applications menu, or run `pqotp-gui`. Create or open
a vault, then watch the live one-time codes refresh every second with a
per-code countdown — double-click a row (or *Copy code*) to copy the current
code; the clipboard auto-clears after 25 s. Add accounts by hand or paste an
`otpauth://` URI, then *Save Vault*.

## CLI usage

```sh
# Create a post-quantum hybrid vault (default ~/.pqotp/vault.potv)
pqotp init                       # add --no-hybrid or --aes to change defaults

# Add an account from a QR-code's otpauth:// URI
pqotp add "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

# ...or by hand
pqotp add -i AWS -a root -s GEZDGNBVGY3TQOJQ --algo SHA256 --digits 8

pqotp list                       # accounts only, never the codes
pqotp code                       # current codes for every account
pqotp code github                # filter by issuer/account substring
pqotp remove 0                   # delete the account at index 0
```

Use `-f FILE` before any command to point at a different vault.

## License

MIT.
