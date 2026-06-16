/*
 * main.c - PQOTP command-line interface.
 *
 * A post-quantum two-factor (TOTP/HOTP) authenticator. OTP secrets live in a
 * single encrypted vault sharing PQPMan's security model: Argon2id + a
 * Kyber-1024/X448 hybrid KEM over AES-256-GCM / XChaCha20-Poly1305, unlocked
 * by one master password. Codes are computed in locked memory and the master
 * password is wiped immediately after key derivation.
 *
 * Commands:
 *   pqotp init                       create a new empty vault
 *   pqotp add <otpauth-uri>          add an account from an otpauth:// URI
 *   pqotp add -i ISSUER -a ACCOUNT -s BASE32SECRET [--algo SHA1|SHA256|SHA512]
 *                                    [--digits N] [--period S]
 *   pqotp list                       list accounts (no codes)
 *   pqotp code [filter]              print current codes (optionally filtered)
 *   pqotp remove <index>             delete the account at <index>
 *
 * Options:
 *   -f, --file PATH   vault file (default ~/.pqotp/vault.potv)
 *       --no-hybrid   create a password-only vault (init only)
 *       --aes         use AES-256-GCM instead of XChaCha20-Poly1305 (init only)
 */
#include "otp_vault.h"
#include "totp.h"

#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#ifndef PQOTP_VERSION
#define PQOTP_VERSION "0.0.0"
#endif

#define PW_MAX 512

/* ----- master-password prompt (no echo) --------------------------------- */

static int read_password(const char *prompt, char *buf, size_t cap) {
    fputs(prompt, stderr);
    fflush(stderr);

    struct termios old, no_echo;
    int have_tty = (tcgetattr(STDIN_FILENO, &old) == 0);
    if (have_tty) {
        no_echo = old;
        no_echo.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo);
    }
    char *r = fgets(buf, (int)cap, stdin);
    if (have_tty) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        fputc('\n', stderr);
    }
    if (!r) { buf[0] = '\0'; return -1; }
    size_t n = strlen(buf);
    if (n && buf[n - 1] == '\n') buf[n - 1] = '\0';
    return 0;
}

/* ----- vault path resolution -------------------------------------------- */

static const char *default_vault_path(char *buf, size_t cap) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : NULL;
    }
    if (!home) return NULL;
    snprintf(buf, cap, "%s/.pqotp/vault.potv", home);
    return buf;
}

/* Ensure the parent directory of `path` exists (mode 0700). */
static void ensure_parent_dir(const char *path) {
    char dir[4096];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash || slash == dir) return;
    *slash = '\0';
    mkdir(dir, 0700);   /* best effort; ignore EEXIST */
}

static otp_algo_t parse_algo(const char *s) {
    if (strcasecmp(s, "SHA256") == 0) return OTP_SHA256;
    if (strcasecmp(s, "SHA512") == 0) return OTP_SHA512;
    return OTP_SHA1;
}

/* ----- usage ------------------------------------------------------------ */

static void usage(FILE *f) {
    fprintf(f,
"PQOTP %s - post-quantum TOTP/HOTP authenticator\n\n"
"Usage:\n"
"  pqotp [-f FILE] init [--no-hybrid] [--aes]\n"
"  pqotp [-f FILE] add <otpauth://...>\n"
"  pqotp [-f FILE] add -i ISSUER -a ACCOUNT -s BASE32SECRET\n"
"                      [--algo SHA1|SHA256|SHA512] [--digits N] [--period S]\n"
"  pqotp [-f FILE] list\n"
"  pqotp [-f FILE] code [filter]\n"
"  pqotp [-f FILE] remove <index>\n\n"
"Default vault: ~/.pqotp/vault.potv\n",
    PQOTP_VERSION);
}

/* ----- commands --------------------------------------------------------- */

static int cmd_init(const char *path, int argc, char **argv) {
    int hybrid = 1;
    vault_cipher_t cipher = VAULT_CIPHER_XCHACHA20_POLY1305;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--no-hybrid") == 0) hybrid = 0;
        else if (strcmp(argv[i], "--aes") == 0) cipher = VAULT_CIPHER_AES_256_GCM;
        else { fprintf(stderr, "init: unknown option '%s'\n", argv[i]); return 2; }
    }

    struct stat st;
    if (stat(path, &st) == 0) {
        fprintf(stderr, "Refusing to overwrite existing vault: %s\n", path);
        return 1;
    }

    char pw[PW_MAX], pw2[PW_MAX];
    if (read_password("Choose a master password: ", pw, sizeof(pw)) != 0 || !pw[0]) {
        fprintf(stderr, "A master password is required.\n"); return 1;
    }
    if (read_password("Confirm master password: ", pw2, sizeof(pw2)) != 0 ||
        strcmp(pw, pw2) != 0) {
        sodium_memzero(pw, sizeof(pw)); sodium_memzero(pw2, sizeof(pw2));
        fprintf(stderr, "Passwords do not match.\n"); return 1;
    }
    sodium_memzero(pw2, sizeof(pw2));

    otp_vault_t *v = otp_vault_new(cipher, VAULT_KDF_MEDIUM, hybrid);
    if (!v) { sodium_memzero(pw, sizeof(pw)); fprintf(stderr, "Out of memory.\n"); return 1; }

    ensure_parent_dir(path);
    char err[256] = {0};
    int rc = otp_vault_save(v, path, pw, err, sizeof(err));
    sodium_memzero(pw, sizeof(pw));
    otp_vault_free(v);
    if (rc != 0) { fprintf(stderr, "Failed to create vault: %s\n", err); return 1; }
    fprintf(stderr, "Created %s vault at %s\n",
            hybrid ? "post-quantum hybrid" : "password-only", path);
    return 0;
}

/* Unlock helper: prompts for the password, loads the vault. */
static otp_vault_t *unlock(const char *path, char *pw, size_t pwcap) {
    if (read_password("Master password: ", pw, pwcap) != 0 || !pw[0]) {
        fprintf(stderr, "A master password is required.\n"); return NULL;
    }
    char err[256] = {0};
    otp_vault_t *v = NULL;
    if (otp_vault_load(path, pw, &v, err, sizeof(err)) != 0) {
        fprintf(stderr, "%s\n", err);
        return NULL;
    }
    return v;
}

static int cmd_add(const char *path, int argc, char **argv) {
    char issuer[256] = "", account[256] = "";
    char secret_b32[256] = "";
    const char *uri = NULL;
    otp_algo_t algo = OTP_SHA1;
    int digits = 6, period = 30;

    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (strncmp(a, "otpauth://", 10) == 0) uri = a;
        else if ((!strcmp(a, "-i") || !strcmp(a, "--issuer")) && i + 1 < argc)
            snprintf(issuer, sizeof(issuer), "%s", argv[++i]);
        else if ((!strcmp(a, "-a") || !strcmp(a, "--account")) && i + 1 < argc)
            snprintf(account, sizeof(account), "%s", argv[++i]);
        else if ((!strcmp(a, "-s") || !strcmp(a, "--secret")) && i + 1 < argc)
            snprintf(secret_b32, sizeof(secret_b32), "%s", argv[++i]);
        else if (!strcmp(a, "--algo") && i + 1 < argc) algo = parse_algo(argv[++i]);
        else if (!strcmp(a, "--digits") && i + 1 < argc) digits = atoi(argv[++i]);
        else if (!strcmp(a, "--period") && i + 1 < argc) period = atoi(argv[++i]);
        else { fprintf(stderr, "add: unexpected argument '%s'\n", a); return 2; }
    }

    uint8_t secret[OTP_MAX_SECRET_LEN];
    size_t secret_len = 0;

    if (uri) {
        if (otp_parse_uri(uri, issuer, account, secret, &secret_len,
                          &algo, &digits, &period) != 0) {
            fprintf(stderr, "Could not parse otpauth URI.\n"); return 1;
        }
    } else {
        if (!account[0] || !secret_b32[0]) {
            fprintf(stderr, "add: need an otpauth:// URI, or at least -a ACCOUNT and -s SECRET.\n");
            return 2;
        }
        int n = otp_base32_decode(secret_b32, secret, sizeof(secret));
        sodium_memzero(secret_b32, sizeof(secret_b32));
        if (n <= 0) { fprintf(stderr, "Invalid base32 secret.\n"); return 1; }
        secret_len = (size_t)n;
    }
    if (digits < 6 || digits > 10) digits = 6;
    if (period <= 0 || period > 600) period = 30;

    char pw[PW_MAX];
    otp_vault_t *v = unlock(path, pw, sizeof(pw));
    if (!v) { sodium_memzero(secret, sizeof(secret)); sodium_memzero(pw, sizeof(pw)); return 1; }

    int rc = 1;
    if (otp_vault_add(v, issuer, account, secret, secret_len,
                      algo, digits, period) == (size_t)-1) {
        fprintf(stderr, "Failed to add entry.\n");
    } else {
        char err[256] = {0};
        if (otp_vault_save(v, path, pw, err, sizeof(err)) != 0) {
            fprintf(stderr, "Failed to save vault: %s\n", err);
        } else {
            fprintf(stderr, "Added %s%s%s.\n",
                    issuer[0] ? issuer : "", issuer[0] ? " / " : "", account);
            rc = 0;
        }
    }
    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(pw, sizeof(pw));
    otp_vault_free(v);
    return rc;
}

static int cmd_list(const char *path) {
    char pw[PW_MAX];
    otp_vault_t *v = unlock(path, pw, sizeof(pw));
    sodium_memzero(pw, sizeof(pw));
    if (!v) return 1;
    size_t n = otp_vault_count(v);
    if (n == 0) { fprintf(stderr, "Vault is empty.\n"); otp_vault_free(v); return 0; }
    printf("%-4s  %-20s  %-28s  %-7s %s\n", "#", "ISSUER", "ACCOUNT", "ALGO", "DIG/PER");
    for (size_t i = 0; i < n; i++) {
        const otp_entry_t *e = otp_vault_get(v, i);
        printf("%-4zu  %-20s  %-28s  %-7s %d/%ds\n",
               i, e->issuer[0] ? e->issuer : "-", e->account,
               otp_algo_name(e->algo), e->digits, e->period);
    }
    otp_vault_free(v);
    return 0;
}

/* Case-insensitive substring test. */
static int matches(const otp_entry_t *e, const char *filter) {
    if (!filter) return 1;
    char hay[600];
    snprintf(hay, sizeof(hay), "%s %s", e->issuer, e->account);
    for (char *p = hay; *p; p++) *p = (char)tolower((unsigned char)*p);
    char low[256];
    snprintf(low, sizeof(low), "%s", filter);
    for (char *p = low; *p; p++) *p = (char)tolower((unsigned char)*p);
    return strstr(hay, low) != NULL;
}

static int cmd_code(const char *path, const char *filter) {
    char pw[PW_MAX];
    otp_vault_t *v = unlock(path, pw, sizeof(pw));
    sodium_memzero(pw, sizeof(pw));
    if (!v) return 1;

    time_t now = time(NULL);
    size_t n = otp_vault_count(v), shown = 0;
    printf("%-20s  %-28s  %-12s %s\n", "ISSUER", "ACCOUNT", "CODE", "EXPIRES");
    for (size_t i = 0; i < n; i++) {
        const otp_entry_t *e = otp_vault_get(v, i);
        if (!matches(e, filter)) continue;
        char code[16]; int remaining = 0;
        if (otp_totp(e->secret, e->secret_len, e->algo, now,
                     e->period, e->digits, code, sizeof(code), &remaining) != 0) {
            snprintf(code, sizeof(code), "ERROR");
            remaining = 0;
        }
        printf("%-20s  %-28s  %-12s %2ds\n",
               e->issuer[0] ? e->issuer : "-", e->account, code, remaining);
        shown++;
    }
    if (shown == 0) fprintf(stderr, "No matching accounts.\n");
    otp_vault_free(v);
    return shown ? 0 : 1;
}

static int cmd_remove(const char *path, const char *idxarg) {
    char *endp = NULL;
    long idx = strtol(idxarg, &endp, 10);
    if (!endp || *endp || idx < 0) { fprintf(stderr, "Invalid index.\n"); return 2; }

    char pw[PW_MAX];
    otp_vault_t *v = unlock(path, pw, sizeof(pw));
    if (!v) { sodium_memzero(pw, sizeof(pw)); return 1; }

    int rc = 1;
    const otp_entry_t *e = otp_vault_get(v, (size_t)idx);
    if (!e) {
        fprintf(stderr, "No entry at index %ld.\n", idx);
    } else {
        char label[600];
        snprintf(label, sizeof(label), "%s%s%s",
                 e->issuer[0] ? e->issuer : "", e->issuer[0] ? " / " : "", e->account);
        otp_vault_remove(v, (size_t)idx);
        char err[256] = {0};
        if (otp_vault_save(v, path, pw, err, sizeof(err)) != 0)
            fprintf(stderr, "Failed to save vault: %s\n", err);
        else { fprintf(stderr, "Removed %s.\n", label); rc = 0; }
    }
    sodium_memzero(pw, sizeof(pw));
    otp_vault_free(v);
    return rc;
}

/* ----- entry point ------------------------------------------------------ */

int main(int argc, char **argv) {
    if (otp_vault_init() != 0) {
        fprintf(stderr, "Failed to initialise crypto library.\n");
        return 1;
    }

    char pathbuf[4096];
    const char *path = NULL;

    /* Leading global options: -f/--file, -h/--help, --version. */
    int i = 1;
    for (; i < argc; i++) {
        if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) && i + 1 < argc)
            path = argv[++i];
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(stdout); return 0; }
        else if (!strcmp(argv[i], "--version")) { printf("pqotp %s\n", PQOTP_VERSION); return 0; }
        else break;
    }
    if (i >= argc) { usage(stderr); return 2; }

    const char *cmd = argv[i++];
    int rest_argc = argc - i;
    char **rest_argv = argv + i;

    if (!path && !(path = default_vault_path(pathbuf, sizeof(pathbuf)))) {
        fprintf(stderr, "Cannot determine home directory; use -f FILE.\n");
        return 1;
    }

    if (!strcmp(cmd, "init"))   return cmd_init(path, rest_argc, rest_argv);
    if (!strcmp(cmd, "add"))    return cmd_add(path, rest_argc, rest_argv);
    if (!strcmp(cmd, "list"))   return cmd_list(path);
    if (!strcmp(cmd, "code"))   return cmd_code(path, rest_argc ? rest_argv[0] : NULL);
    if (!strcmp(cmd, "remove") || !strcmp(cmd, "rm")) {
        if (rest_argc < 1) { fprintf(stderr, "remove: need an index.\n"); return 2; }
        return cmd_remove(path, rest_argv[0]);
    }

    fprintf(stderr, "Unknown command '%s'.\n\n", cmd);
    usage(stderr);
    return 2;
}
