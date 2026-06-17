/*
 * gui.c - PQOTP: post-quantum TOTP/HOTP authenticator (GTK3 front-end).
 *
 * The window holds a GtkStack with two faces:
 *   - the "lock" view: open an existing vault or create a new one, unlocked
 *     with the master password;
 *   - the "vault" view: the live list of one-time codes (refreshed every
 *     second with a per-code countdown), plus an editor to add accounts by
 *     hand or by pasting an otpauth:// URI.
 *
 * All cryptography lives in otp_vault.c (AES-256-GCM / XChaCha20-Poly1305 over
 * a single AEAD blob, Argon2id master key, optional Kyber-1024 + X448 hybrid
 * KEM) and the OTP maths in totp.c. The slow Argon2id step runs on a worker
 * thread so the UI never freezes; the master password is held in libsodium
 * guarded memory for the session and wiped on lock/exit.
 */
#include <gtk/gtk.h>
#include <sodium.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "otp_vault.h"
#include "totp.h"
#include "secure_buffer.h"

#ifndef PQOTP_VERSION
#define PQOTP_VERSION "0.1.1"
#endif
#define APP_ID "org.pqotp.PQOTP"
#define PASSWORD_MAX 4096
#define CLIPBOARD_CLEAR_SECONDS 25

/* ----- cyber theme (shared with PQPMan) --------------------------------- */

static const char *APP_CSS =
    "window, .pq-root { background-color: #070b12; color: #c8f7ff; }"
    "headerbar, .titlebar {"
    "  background: linear-gradient(90deg, #0a0f1a, #0e1726, #0a0f1a);"
    "  border-bottom: 1px solid #b026ff;"
    "  box-shadow: 0 1px 8px rgba(176,38,255,0.35); min-height: 40px; }"
    ".hb-title { color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  letter-spacing: 2px; }"
    "headerbar button { padding: 2px 10px; margin: 4px 2px; min-height: 0;"
    "  min-width: 0; letter-spacing: 0; }"
    "headerbar button.titlebutton { padding: 2px; margin: 2px;"
    "  min-height: 22px; min-width: 22px; }"
    "label { color: #9fd6e6; font-family: monospace; }"
    ".field-label { color: #5fb4c9; letter-spacing: 1px; }"
    ".brand { color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  font-size: 24px; letter-spacing: 6px; }"
    ".subtitle { color: #3d7d8f; font-size: 10px; letter-spacing: 4px; }"
    ".section { color: #b026ff; font-family: monospace; letter-spacing: 2px;"
    "  font-weight: bold; }"
    ".code-cell { color: #39ff14; font-family: monospace; font-weight: bold;"
    "  font-size: 16px; letter-spacing: 3px; }"
    "entry { background-color: #0c1421; color: #d8feff; border: 1px solid #14384a;"
    "  border-radius: 4px; padding: 7px; font-family: monospace; caret-color: #00e5ff; }"
    "entry:focus { border-color: #00e5ff; box-shadow: 0 0 6px rgba(0,229,255,0.6); }"
    "combobox box, combobox button, combobox { background-color: #0c1421;"
    "  color: #d8feff; border: 1px solid #14384a; border-radius: 4px;"
    "  font-family: monospace; }"
    "combobox button:hover { border-color: #00e5ff; }"
    "spinbutton, spinbutton entry, spinbutton button { background-color: #0c1421;"
    "  color: #d8feff; border: 1px solid #14384a; font-family: monospace; }"
    "checkbutton { color: #9fd6e6; font-family: monospace; }"
    "radiobutton, checkbutton { color: #9fd6e6; font-family: monospace; }"
    "radiobutton check, checkbutton check { background-color: #0c1421;"
    "  border: 1px solid #2a6b80; }"
    "radiobutton check:checked, checkbutton check:checked {"
    "  background-color: #00e5ff; border-color: #00e5ff; }"
    "button { background: #0e1b2b; color: #9fe9ff; border: 1px solid #1d4c5e;"
    "  border-radius: 4px; padding: 6px 12px; font-family: monospace; letter-spacing: 1px; }"
    "button:hover { border-color: #00e5ff; color: #ffffff;"
    "  box-shadow: 0 0 8px rgba(0,229,255,0.45); }"
    "button:active { background: #102a3a; }"
    "button:disabled { color: #3a566a; border-color: #16313e; }"
    ".action-button { background: linear-gradient(90deg, #7d1bd6, #b026ff);"
    "  color: #ffffff; font-weight: bold; letter-spacing: 2px; border: 1px solid #b026ff; }"
    ".action-button:hover { box-shadow: 0 0 14px rgba(176,38,255,0.8); color: #ffffff; }"
    ".accent-button { background: linear-gradient(90deg, #00b3c4, #00e5ff);"
    "  color: #000000; font-weight: bold; border: 1px solid #00e5ff; }"
    ".accent-button label { color: #000000; }"
    ".accent-button:hover, .accent-button:hover label { color: #000000; }"
    ".danger-button { border-color: #ff426f; color: #ff7a98; }"
    ".danger-button:hover { box-shadow: 0 0 8px rgba(255,66,111,0.5); color: #ffffff; }"
    "treeview { background-color: #0a121e; color: #c8f7ff; font-family: monospace; }"
    "treeview:selected { background-color: #16314a; color: #ffffff; }"
    "treeview header button { background: #0e1b2b; color: #5fb4c9;"
    "  border: 1px solid #14384a; font-family: monospace; }"
    "progressbar text { color: #9fe9ff; font-family: monospace; font-size: 10px; }"
    "progressbar trough { background-color: #0c1421; border: 1px solid #14384a;"
    "  border-radius: 4px; min-height: 16px; }"
    "progressbar progress { background: linear-gradient(90deg, #7d1bd6, #b026ff);"
    "  border-radius: 4px; min-height: 16px; box-shadow: 0 0 10px rgba(176,38,255,0.6); }"
    ".status-ok { color: #39ff14; }"
    ".status-err { color: #ff426f; }"
    ".status-run { color: #00e5ff; }";

/* ----- tree model columns ----------------------------------------------- */

enum { COL_ISSUER, COL_ACCOUNT, COL_CODE, COL_EXPIRES, COL_IDX, N_COLS };

/* ----- app state -------------------------------------------------------- */

typedef struct Job Job;

typedef struct {
    GtkApplication *gapp;
    GtkWidget *window;
    GtkWidget *stack;

    /* lock view */
    GtkWidget *lk_path;
    GtkWidget *lk_open_radio;
    GtkWidget *lk_new_radio;
    GtkWidget *lk_pass;
    GtkWidget *lk_confirm;
    GtkWidget *lk_confirm_row;
    GtkWidget *lk_cipher;
    GtkWidget *lk_kdf;
    GtkWidget *lk_hybrid;
    GtkWidget *lk_create_box;
    GtkWidget *lk_button;
    GtkWidget *lk_progress;
    GtkWidget *lk_status;

    /* vault view */
    GtkWidget *vw_tree;
    GtkListStore *store;
    GtkWidget *ed_issuer;
    GtkWidget *ed_account;
    GtkWidget *ed_secret;
    GtkWidget *ed_algo;
    GtkWidget *ed_digits;
    GtkWidget *ed_period;
    GtkWidget *ed_uri;
    GtkWidget *vw_meta;
    GtkWidget *vw_status;

    /* session */
    otp_vault_t *vault;
    char        *vault_path;
    char        *master;        /* sodium guarded, PASSWORD_MAX */
    gboolean     dirty;
    guint        tick_id;       /* 1 Hz code refresh */

    guint        pulse_id;
    gboolean     pulsing;
    volatile int window_gone;
    Job * volatile current_job;
} App;

struct Job {
    App *app;
    int  kind;                  /* 0 = load, 1 = save */
    int  created;               /* save: this is the initial create of a vault */
    char path[4096];
    char password[PASSWORD_MAX];
    otp_vault_t *vault;         /* save: borrowed */
    int  rc;
    char err[256];
    otp_vault_t *loaded;        /* load result */
};

/* ----- forward decls ---------------------------------------------------- */
static void show_vault_view(App *app);
static void refresh_store(App *app);
static void refresh_codes(App *app);
static void set_dirty(App *app, gboolean dirty);
static void update_window_title(App *app);

/* ----- misc helpers ----------------------------------------------------- */

static void add_class(GtkWidget *w, const char *cls) {
    gtk_style_context_add_class(gtk_widget_get_style_context(w), cls);
}

static void set_status_class(GtkWidget *label, const char *cls, const char *text) {
    GtkStyleContext *sc = gtk_widget_get_style_context(label);
    gtk_style_context_remove_class(sc, "status-ok");
    gtk_style_context_remove_class(sc, "status-err");
    gtk_style_context_remove_class(sc, "status-run");
    if (cls) gtk_style_context_add_class(sc, cls);
    gtk_label_set_text(GTK_LABEL(label), text);
}

static void info_dialog(App *app, GtkMessageType type, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    char *msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, type, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    g_free(msg);
}

static gboolean confirm_dialog(App *app, const char *msg) {
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", msg);
    int r = gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    return r == GTK_RESPONSE_YES;
}

static const char *default_vault_path(void) {
    static char path[4096];
    const char *base = g_get_user_data_dir();
    g_snprintf(path, sizeof(path), "%s/pqotp", base);
    g_mkdir_with_parents(path, 0700);
    g_strlcat(path, "/vault.potv", sizeof(path));
    return path;
}

static GtkWidget *labeled_row(const char *text, GtkWidget *w, GtkWidget *extra) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl = gtk_label_new(text);
    gtk_widget_set_size_request(lbl, 110, -1);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    add_class(lbl, "field-label");
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), w, TRUE, TRUE, 0);
    if (extra) gtk_box_pack_start(GTK_BOX(box), extra, FALSE, FALSE, 0);
    return box;
}

/* ----- clipboard (auto-clear) ------------------------------------------- */

static gboolean clipboard_clear_cb(gpointer data) {
    char *secret = data;
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    char *cur = gtk_clipboard_wait_for_text(cb);
    if (cur && strcmp(cur, secret) == 0)
        gtk_clipboard_set_text(cb, "", -1);
    g_free(cur);
    g_free(secret);
    return G_SOURCE_REMOVE;
}

static void copy_to_clipboard(App *app, const char *text, const char *what) {
    if (!text || !*text) return;
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, text, -1);
    g_timeout_add_seconds(CLIPBOARD_CLEAR_SECONDS, clipboard_clear_cb, g_strdup(text));
    char msg[128];
    g_snprintf(msg, sizeof(msg), "\xE2\x9C\x94 %s copied (clipboard clears in %ds)",
               what, CLIPBOARD_CLEAR_SECONDS);
    set_status_class(app->vw_status, "status-ok", msg);
}

/* ----- worker thread (load / save) -------------------------------------- */

static gboolean pulse_cb(gpointer data) {
    App *app = data;
    if (!app->pulsing || app->window_gone) { app->pulse_id = 0; return G_SOURCE_REMOVE; }
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->lk_progress));
    return G_SOURCE_CONTINUE;
}

static void start_pulse(App *app, const char *text) {
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->lk_progress), text);
    app->pulsing = TRUE;
    if (app->pulse_id == 0)
        app->pulse_id = g_timeout_add(110, pulse_cb, app);
}

static gboolean job_done_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;
    app->current_job = NULL;
    app->pulsing = FALSE;

    if (app->window_gone) {
        if (job->loaded) otp_vault_free(job->loaded);
        if (app->vault) otp_vault_free(app->vault);
        sodium_munlock(job->password, sizeof(job->password));
        g_free(job);
        g_application_release(G_APPLICATION(app->gapp));
        if (app->master) sodium_free(app->master);
        g_free(app->vault_path);
        g_free(app);
        return G_SOURCE_REMOVE;
    }

    if (job->kind == 0) {   /* load */
        gtk_widget_set_sensitive(app->lk_button, TRUE);
        if (job->rc == 0) {
            app->vault = job->loaded;
            g_free(app->vault_path);
            app->vault_path = g_strdup(job->path);
            g_strlcpy(app->master, job->password, PASSWORD_MAX);
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->lk_progress), 1.0);
            gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->lk_progress), "unlocked");
            set_status_class(app->lk_status, "status-ok", "\xE2\x9C\x94 Vault unlocked.");
            show_vault_view(app);
        } else {
            if (job->loaded) otp_vault_free(job->loaded);
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->lk_progress), 0.0);
            gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->lk_progress), "locked");
            char m[300]; g_snprintf(m, sizeof(m), "\xE2\x9C\x96 %s", job->err);
            set_status_class(app->lk_status, "status-err", m);
        }
    } else if (job->created) {   /* initial create-save (still on lock view) */
        gtk_widget_set_sensitive(app->lk_button, TRUE);
        if (job->rc == 0) {
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->lk_progress), 1.0);
            gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->lk_progress), "unlocked");
            set_status_class(app->lk_status, "status-ok", "\xE2\x9C\x94 Vault created.");
            show_vault_view(app);
        } else {
            /* Roll back the half-created session and stay on the lock view. */
            if (app->vault) { otp_vault_free(app->vault); app->vault = NULL; }
            sodium_memzero(app->master, PASSWORD_MAX);
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->lk_progress), 0.0);
            gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->lk_progress), "locked");
            char m[300]; g_snprintf(m, sizeof(m), "\xE2\x9C\x96 %s", job->err);
            set_status_class(app->lk_status, "status-err", m);
            info_dialog(app, GTK_MESSAGE_ERROR, "%s", job->err);
        }
    } else {                /* save */
        if (job->rc == 0) {
            set_dirty(app, FALSE);
            set_status_class(app->vw_status, "status-ok", "\xE2\x9C\x94 Vault saved.");
        } else {
            char m[300]; g_snprintf(m, sizeof(m), "\xE2\x9C\x96 %s", job->err);
            set_status_class(app->vw_status, "status-err", m);
            info_dialog(app, GTK_MESSAGE_ERROR, "%s", job->err);
        }
        gtk_widget_set_sensitive(app->window, TRUE);
    }

    sodium_munlock(job->password, sizeof(job->password));
    g_free(job);
    g_application_release(G_APPLICATION(app->gapp));
    return G_SOURCE_REMOVE;
}

static gpointer worker_thread(gpointer data) {
    Job *job = data;
    if (job->kind == 0)
        job->rc = otp_vault_load(job->path, job->password, &job->loaded,
                                 job->err, sizeof(job->err));
    else
        job->rc = otp_vault_save(job->vault, job->path, job->password,
                                 job->err, sizeof(job->err));
    g_idle_add(job_done_idle, job);
    return NULL;
}

static Job *start_job(App *app, int kind) {
    Job *job = g_new0(Job, 1);
    sodium_mlock(job->password, sizeof(job->password));
    job->app = app;
    job->kind = kind;
    app->current_job = job;
    g_application_hold(G_APPLICATION(app->gapp));
    return job;
}

static void spawn_job(App *app, Job *job) {
    GError *gerr = NULL;
    GThread *t = g_thread_try_new("pqotp-worker", worker_thread, job, &gerr);
    if (!t) {
        app->current_job = NULL;
        app->pulsing = FALSE;
        sodium_munlock(job->password, sizeof(job->password));
        g_application_release(G_APPLICATION(app->gapp));
        gtk_widget_set_sensitive(app->window, TRUE);
        gtk_widget_set_sensitive(app->lk_button, TRUE);
        info_dialog(app, GTK_MESSAGE_ERROR, "Could not start worker thread.");
        g_free(job);
        if (gerr) g_error_free(gerr);
        return;
    }
    g_thread_unref(t);
}

/* ----- lock view logic -------------------------------------------------- */

static void on_lock_mode_toggled(GtkToggleButton *btn, gpointer user) {
    (void)btn;
    App *app = user;
    gboolean creating = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->lk_new_radio));
    gtk_widget_set_visible(app->lk_create_box, creating);
    gtk_widget_set_visible(app->lk_confirm_row, creating);
    gtk_button_set_label(GTK_BUTTON(app->lk_button), creating ? "CREATE VAULT" : "UNLOCK");
}

static void on_lock_browse(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    gboolean creating = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->lk_new_radio));
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        creating ? "Choose vault location" : "Open vault",
        GTK_WINDOW(app->window),
        creating ? GTK_FILE_CHOOSER_ACTION_SAVE : GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        creating ? "_Choose" : "_Open", GTK_RESPONSE_ACCEPT, NULL);
    if (creating)
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        gtk_entry_set_text(GTK_ENTRY(app->lk_path), f);
        g_free(f);
    }
    gtk_widget_destroy(dlg);
}

static void on_unlock_or_create(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    gboolean creating = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->lk_new_radio));
    const char *path = gtk_entry_get_text(GTK_ENTRY(app->lk_path));
    const char *pw   = gtk_entry_get_text(GTK_ENTRY(app->lk_pass));

    if (!app->master) {
        info_dialog(app, GTK_MESSAGE_ERROR,
                    "Could not allocate secure memory for the master password. "
                    "Raise the locked-memory limit (RLIMIT_MEMLOCK) and restart.");
        return;
    }
    if (!path || !*path) { info_dialog(app, GTK_MESSAGE_WARNING, "Choose a vault file."); return; }
    if (!pw || !*pw)     { info_dialog(app, GTK_MESSAGE_WARNING, "Enter a master password."); return; }
    if (strlen(pw) >= PASSWORD_MAX) {
        info_dialog(app, GTK_MESSAGE_WARNING, "Master password is too long."); return;
    }

    if (creating) {
        const char *cf = gtk_entry_get_text(GTK_ENTRY(app->lk_confirm));
        if (!cf || strcmp(pw, cf) != 0) {
            info_dialog(app, GTK_MESSAGE_WARNING, "The passwords do not match."); return;
        }
        if (g_file_test(path, G_FILE_TEST_EXISTS) &&
            !confirm_dialog(app, "That file already exists. Overwrite it with a new, empty vault?"))
            return;

        const char *cid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->lk_cipher));
        const char *kid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->lk_kdf));
        vault_cipher_t cipher = cid ? (vault_cipher_t)atoi(cid) : VAULT_CIPHER_XCHACHA20_POLY1305;
        vault_kdf_t kdf = kid ? (vault_kdf_t)atoi(kid) : VAULT_KDF_MEDIUM;
        int hybrid = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->lk_hybrid)) ? 1 : 0;

        otp_vault_t *v = otp_vault_new(cipher, kdf, hybrid);
        if (!v) { info_dialog(app, GTK_MESSAGE_ERROR, "Out of memory."); return; }

        app->vault = v;
        g_free(app->vault_path);
        app->vault_path = g_strdup(path);
        g_strlcpy(app->master, pw, PASSWORD_MAX);

        /* Persist the empty vault on a worker thread. Stay on the lock view
         * until it succeeds, so a failed save never strands the user in the
         * vault view for a file that was never written. */
        gtk_widget_set_sensitive(app->lk_button, FALSE);
        start_pulse(app, "deriving key\xE2\x80\xA6");
        set_status_class(app->lk_status, "status-run",
                         "\xE2\x96\xB6 Creating vault\xE2\x80\xA6 (deriving key)");
        Job *job = start_job(app, 1);
        job->created = 1;
        g_strlcpy(job->path, path, sizeof(job->path));
        g_strlcpy(job->password, pw, sizeof(job->password));
        job->vault = app->vault;
        spawn_job(app, job);
        return;
    }

    if (!g_file_test(path, G_FILE_TEST_EXISTS)) {
        info_dialog(app, GTK_MESSAGE_WARNING,
                    "No vault at that path. Switch to \"Create new\" to make one.");
        return;
    }

    gtk_widget_set_sensitive(app->lk_button, FALSE);
    start_pulse(app, "deriving key\xE2\x80\xA6");
    set_status_class(app->lk_status, "status-run",
                     "\xE2\x96\xB6 Unlocking\xE2\x80\xA6 (deriving key, this may take a moment)");
    Job *job = start_job(app, 0);
    g_strlcpy(job->path, path, sizeof(job->path));
    g_strlcpy(job->password, pw, sizeof(job->password));
    spawn_job(app, job);
}

/* ----- vault view: code list -------------------------------------------- */

static otp_algo_t algo_from_combo(App *app) {
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->ed_algo));
    return id ? (otp_algo_t)atoi(id) : OTP_SHA1;
}

static void refresh_store(App *app) {
    gtk_list_store_clear(app->store);
    size_t n = otp_vault_count(app->vault);
    for (size_t i = 0; i < n; i++) {
        const otp_entry_t *e = otp_vault_get(app->vault, i);
        GtkTreeIter it;
        gtk_list_store_append(app->store, &it);
        gtk_list_store_set(app->store, &it,
                           COL_ISSUER, e->issuer[0] ? e->issuer : "-",
                           COL_ACCOUNT, e->account,
                           COL_CODE, "------",
                           COL_EXPIRES, "",
                           COL_IDX, (guint)i, -1);
    }
    refresh_codes(app);
}

/* Recompute every visible code + countdown in place (keeps selection). */
static void refresh_codes(App *app) {
    if (!app->vault) return;
    time_t now = time(NULL);
    GtkTreeModel *m = GTK_TREE_MODEL(app->store);
    GtkTreeIter it;
    if (!gtk_tree_model_get_iter_first(m, &it)) return;
    do {
        guint idx = 0;
        gtk_tree_model_get(m, &it, COL_IDX, &idx, -1);
        const otp_entry_t *e = otp_vault_get(app->vault, idx);
        if (!e) continue;
        char code[16]; int remaining = 0;
        if (otp_totp(e->secret, e->secret_len, e->algo, now,
                     e->period, e->digits, code, sizeof(code), &remaining) != 0)
            g_strlcpy(code, "ERROR", sizeof(code));
        char exp[16];
        g_snprintf(exp, sizeof(exp), "%ds", remaining);
        gtk_list_store_set(app->store, &it, COL_CODE, code, COL_EXPIRES, exp, -1);
    } while (gtk_tree_model_iter_next(m, &it));
}

static gboolean tick_cb(gpointer user) {
    App *app = user;
    if (app->window_gone || !app->vault) { app->tick_id = 0; return G_SOURCE_REMOVE; }
    refresh_codes(app);
    return G_SOURCE_CONTINUE;
}

/* Return the vault index of the selected row, or -1. */
static gssize selected_index(App *app) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->vw_tree));
    GtkTreeModel *m; GtkTreeIter it;
    if (!gtk_tree_selection_get_selected(sel, &m, &it)) return -1;
    guint idx = 0;
    gtk_tree_model_get(m, &it, COL_IDX, &idx, -1);
    return (gssize)idx;
}

static void on_copy_code(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    gssize idx = selected_index(app);
    if (idx < 0) { info_dialog(app, GTK_MESSAGE_INFO, "Select an account first."); return; }
    const otp_entry_t *e = otp_vault_get(app->vault, (size_t)idx);
    if (!e) return;
    char code[16];
    if (otp_totp(e->secret, e->secret_len, e->algo, time(NULL),
                 e->period, e->digits, code, sizeof(code), NULL) != 0) {
        info_dialog(app, GTK_MESSAGE_ERROR, "Could not compute code."); return;
    }
    copy_to_clipboard(app, code, "Code");
}

static void on_row_activated(GtkTreeView *tv, GtkTreePath *p,
                             GtkTreeViewColumn *c, gpointer user) {
    (void)tv; (void)p; (void)c;
    on_copy_code(NULL, user);
}

static void clear_editor(App *app) {
    gtk_entry_set_text(GTK_ENTRY(app->ed_issuer), "");
    gtk_entry_set_text(GTK_ENTRY(app->ed_account), "");
    gtk_entry_set_text(GTK_ENTRY(app->ed_secret), "");
    gtk_entry_set_text(GTK_ENTRY(app->ed_uri), "");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->ed_algo), "0");
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->ed_digits), 6);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->ed_period), 30);
}

/* Paste an otpauth:// URI: parse it and fill the form fields. */
static void on_uri_apply(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const char *uri = gtk_entry_get_text(GTK_ENTRY(app->ed_uri));
    if (!uri || !*uri) return;
    char issuer[256], account[256];
    uint8_t secret[OTP_MAX_SECRET_LEN]; size_t slen = 0;
    otp_algo_t algo; int digits, period;
    if (otp_parse_uri(uri, issuer, account, secret, &slen, &algo, &digits, &period) != 0) {
        info_dialog(app, GTK_MESSAGE_WARNING, "Could not parse that otpauth:// URI.");
        return;
    }
    /* Re-encode the secret to base32 for display is non-trivial; instead add
     * the parsed account directly. */
    if (otp_vault_add(app->vault, issuer, account, secret, slen,
                      algo, digits, period) == (size_t)-1) {
        sodium_memzero(secret, sizeof(secret));
        info_dialog(app, GTK_MESSAGE_ERROR, "Out of memory."); return;
    }
    sodium_memzero(secret, sizeof(secret));
    set_dirty(app, TRUE);
    refresh_store(app);
    clear_editor(app);
    set_status_class(app->vw_status, "status-ok",
                     "\xE2\x9C\x94 Account added from URI. Use \xE2\x80\x9CSave Vault\xE2\x80\x9D to write to disk.");
}

static void on_add_account(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const char *issuer  = gtk_entry_get_text(GTK_ENTRY(app->ed_issuer));
    const char *account = gtk_entry_get_text(GTK_ENTRY(app->ed_account));
    const char *secret_b32 = gtk_entry_get_text(GTK_ENTRY(app->ed_secret));

    if (!account || !*account) {
        info_dialog(app, GTK_MESSAGE_WARNING, "Give the account a name."); return;
    }
    if (!secret_b32 || !*secret_b32) {
        info_dialog(app, GTK_MESSAGE_WARNING, "Enter the base32 secret."); return;
    }
    uint8_t secret[OTP_MAX_SECRET_LEN];
    int n = otp_base32_decode(secret_b32, secret, sizeof(secret));
    if (n <= 0) {
        sodium_memzero(secret, sizeof(secret));
        info_dialog(app, GTK_MESSAGE_WARNING, "The secret is not valid base32.");
        return;
    }
    int digits = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(app->ed_digits));
    int period = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(app->ed_period));

    if (otp_vault_add(app->vault, issuer, account, secret, (size_t)n,
                      algo_from_combo(app), digits, period) == (size_t)-1) {
        sodium_memzero(secret, sizeof(secret));
        info_dialog(app, GTK_MESSAGE_ERROR, "Out of memory."); return;
    }
    sodium_memzero(secret, sizeof(secret));
    set_dirty(app, TRUE);
    refresh_store(app);
    clear_editor(app);
    set_status_class(app->vw_status, "status-ok",
                     "\xE2\x9C\x94 Account added. Use \xE2\x80\x9CSave Vault\xE2\x80\x9D to write to disk.");
}

static void on_delete_account(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    gssize idx = selected_index(app);
    if (idx < 0) { info_dialog(app, GTK_MESSAGE_INFO, "Select an account first."); return; }
    if (!confirm_dialog(app, "Delete this account? This cannot be undone after you save the vault."))
        return;
    otp_vault_remove(app->vault, (size_t)idx);
    set_dirty(app, TRUE);
    refresh_store(app);
    set_status_class(app->vw_status, "status-ok",
                     "\xE2\x9C\x94 Account deleted. Use \xE2\x80\x9CSave Vault\xE2\x80\x9D to write to disk.");
}

static void on_save_vault(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    if (!app->vault) return;
    gtk_widget_set_sensitive(app->window, FALSE);
    set_status_class(app->vw_status, "status-run", "\xE2\x96\xB6 Saving\xE2\x80\xA6 (deriving key)");
    Job *job = start_job(app, 1);
    g_strlcpy(job->path, app->vault_path, sizeof(job->path));
    g_strlcpy(job->password, app->master, sizeof(job->password));
    job->vault = app->vault;
    spawn_job(app, job);
}

static void do_lock(App *app) {
    if (app->tick_id) { g_source_remove(app->tick_id); app->tick_id = 0; }
    if (app->vault) { otp_vault_free(app->vault); app->vault = NULL; }
    if (app->master) sodium_memzero(app->master, PASSWORD_MAX);
    set_dirty(app, FALSE);
    gtk_entry_set_text(GTK_ENTRY(app->lk_pass), "");
    if (app->lk_confirm) gtk_entry_set_text(GTK_ENTRY(app->lk_confirm), "");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->lk_open_radio), TRUE);
    gtk_button_set_label(GTK_BUTTON(app->lk_button), "UNLOCK");
    gtk_widget_set_visible(app->lk_create_box, FALSE);
    gtk_widget_set_visible(app->lk_confirm_row, FALSE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->lk_progress), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->lk_progress), "locked");
    set_status_class(app->lk_status, NULL, "Vault locked.");
    gtk_widget_set_sensitive(app->lk_button, TRUE);
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "lock");
    gtk_window_set_title(GTK_WINDOW(app->window), "PQOTP \xE2\x80\x94 locked");
}

static void on_lock_clicked(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    if (app->dirty &&
        !confirm_dialog(app, "You have unsaved changes. Lock anyway and discard them?"))
        return;
    do_lock(app);
}

/* ----- view assembly ---------------------------------------------------- */

static GtkWidget *build_lock_view(App *app) {
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    add_class(root, "pq-root");
    gtk_container_set_border_width(GTK_CONTAINER(root), 22);

    GtkWidget *brand = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(brand),
        "<span foreground='#b026ff'>\xE2\x9B\xA8 P Q</span> O T P");
    gtk_label_set_xalign(GTK_LABEL(brand), 0.5);
    add_class(brand, "brand");
    gtk_box_pack_start(GTK_BOX(root), brand, FALSE, FALSE, 0);
    GtkWidget *sub = gtk_label_new("POST-QUANTUM  2FA  AUTHENTICATOR");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.5);
    add_class(sub, "subtitle");
    gtk_box_pack_start(GTK_BOX(root), sub, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 6);

    GtkWidget *mode = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    app->lk_open_radio = gtk_radio_button_new_with_label(NULL, "Open existing");
    app->lk_new_radio = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(app->lk_open_radio), "Create new");
    gtk_box_pack_start(GTK_BOX(mode), app->lk_open_radio, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode), app->lk_new_radio, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Mode:", mode, NULL), FALSE, FALSE, 0);

    app->lk_path = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app->lk_path), default_vault_path());
    GtkWidget *browse = gtk_button_new_with_label("Browse…");
    g_signal_connect(browse, "clicked", G_CALLBACK(on_lock_browse), app);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Vault file:", app->lk_path, browse), FALSE, FALSE, 0);

    GtkEntryBuffer *pb = secure_entry_buffer_new();
    app->lk_pass = gtk_entry_new_with_buffer(pb);
    g_object_unref(pb);
    gtk_entry_set_visibility(GTK_ENTRY(app->lk_pass), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(app->lk_pass), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_activates_default(GTK_ENTRY(app->lk_pass), TRUE);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Master pass:", app->lk_pass, NULL), FALSE, FALSE, 0);

    GtkEntryBuffer *cb = secure_entry_buffer_new();
    app->lk_confirm = gtk_entry_new_with_buffer(cb);
    g_object_unref(cb);
    gtk_entry_set_visibility(GTK_ENTRY(app->lk_confirm), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(app->lk_confirm), GTK_INPUT_PURPOSE_PASSWORD);
    app->lk_confirm_row = labeled_row("Confirm:", app->lk_confirm, NULL);
    gtk_box_pack_start(GTK_BOX(root), app->lk_confirm_row, FALSE, FALSE, 0);

    app->lk_create_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *secl = gtk_label_new("\xE2\x9C\xA6 NEW VAULT PROTECTION");
    gtk_label_set_xalign(GTK_LABEL(secl), 0.0);
    add_class(secl, "section");
    gtk_box_pack_start(GTK_BOX(app->lk_create_box), secl, FALSE, FALSE, 0);

    app->lk_cipher = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->lk_cipher), "2", "XChaCha20-Poly1305");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->lk_cipher), "1", "AES-256-GCM");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->lk_cipher), "2");
    gtk_box_pack_start(GTK_BOX(app->lk_create_box),
                       labeled_row("Cipher:", app->lk_cipher, NULL), FALSE, FALSE, 0);

    app->lk_kdf = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->lk_kdf), "0", "Basic (256 MiB)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->lk_kdf), "1", "Medium (1 GiB) — minimum");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->lk_kdf), "2", "Strong (4 GiB)");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->lk_kdf), "1");
    gtk_box_pack_start(GTK_BOX(app->lk_create_box),
                       labeled_row("Key strength:", app->lk_kdf, NULL), FALSE, FALSE, 0);

    app->lk_hybrid = gtk_check_button_new_with_label("Post-quantum hybrid (Kyber-1024 + X448)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->lk_hybrid), TRUE);
    gtk_box_pack_start(GTK_BOX(app->lk_create_box),
                       labeled_row("Hybrid PQC:", app->lk_hybrid, NULL), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), app->lk_create_box, FALSE, FALSE, 0);

    app->lk_button = gtk_button_new_with_label("UNLOCK");
    add_class(app->lk_button, "action-button");
    gtk_widget_set_can_default(app->lk_button, TRUE);
    g_signal_connect(app->lk_button, "clicked", G_CALLBACK(on_unlock_or_create), app);
    gtk_box_pack_start(GTK_BOX(root), app->lk_button, FALSE, FALSE, 8);

    app->lk_progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(app->lk_progress), TRUE);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->lk_progress), "locked");
    gtk_box_pack_start(GTK_BOX(root), app->lk_progress, FALSE, FALSE, 0);

    app->lk_status = gtk_label_new("Open your vault or create a new one.");
    gtk_label_set_xalign(GTK_LABEL(app->lk_status), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(app->lk_status), TRUE);
    gtk_box_pack_start(GTK_BOX(root), app->lk_status, FALSE, FALSE, 0);

    g_signal_connect(app->lk_open_radio, "toggled", G_CALLBACK(on_lock_mode_toggled), app);
    g_signal_connect(app->lk_new_radio, "toggled", G_CALLBACK(on_lock_mode_toggled), app);
    return root;
}

static GtkWidget *build_vault_view(App *app) {
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    add_class(root, "pq-root");
    gtk_container_set_border_width(GTK_CONTAINER(root), 12);

    /* toolbar */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *spacer = gtk_label_new("\xF0\x9F\x94\x90  ACCOUNTS");
    add_class(spacer, "section");
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_label_set_xalign(GTK_LABEL(spacer), 0.0);
    GtkWidget *copyb = gtk_button_new_with_label("\xF0\x9F\x93\x8B Copy code");
    GtkWidget *saveb = gtk_button_new_with_label("\xF0\x9F\x92\xBE Save Vault");
    add_class(saveb, "accent-button");
    GtkWidget *lockb = gtk_button_new_with_label("\xF0\x9F\x94\x92 Lock");
    g_signal_connect(copyb, "clicked", G_CALLBACK(on_copy_code), app);
    g_signal_connect(saveb, "clicked", G_CALLBACK(on_save_vault), app);
    g_signal_connect(lockb, "clicked", G_CALLBACK(on_lock_clicked), app);
    gtk_box_pack_start(GTK_BOX(bar), spacer, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(bar), copyb, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), saveb, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), lockb, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), bar, FALSE, FALSE, 0);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(root), paned, TRUE, TRUE, 0);

    /* code list */
    app->store = gtk_list_store_new(N_COLS, G_TYPE_STRING, G_TYPE_STRING,
                                    G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT);
    app->vw_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app->store));
    g_object_unref(app->store);
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    GtkCellRenderer *rc = gtk_cell_renderer_text_new();
    g_object_set(rc, "weight", 700, "scale", 1.3, "foreground", "#39ff14", NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->vw_tree),
        gtk_tree_view_column_new_with_attributes("Issuer", r, "text", COL_ISSUER, NULL));
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->vw_tree),
        gtk_tree_view_column_new_with_attributes("Account", r, "text", COL_ACCOUNT, NULL));
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->vw_tree),
        gtk_tree_view_column_new_with_attributes("Code", rc, "text", COL_CODE, NULL));
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->vw_tree),
        gtk_tree_view_column_new_with_attributes("Expires", r, "text", COL_EXPIRES, NULL));
    g_signal_connect(app->vw_tree, "row-activated", G_CALLBACK(on_row_activated), app);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scroll, 420, -1);
    gtk_container_add(GTK_CONTAINER(scroll), app->vw_tree);
    gtk_paned_pack1(GTK_PANED(paned), scroll, TRUE, FALSE);

    /* editor */
    GtkWidget *form = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(form), 6);
    GtkWidget *fsec = gtk_label_new("\xE2\x9C\xA6 ADD ACCOUNT");
    gtk_label_set_xalign(GTK_LABEL(fsec), 0.0);
    add_class(fsec, "section");
    gtk_box_pack_start(GTK_BOX(form), fsec, FALSE, FALSE, 0);

    app->ed_issuer = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->ed_issuer), "e.g. GitHub");
    gtk_box_pack_start(GTK_BOX(form), labeled_row("Issuer:", app->ed_issuer, NULL), FALSE, FALSE, 0);
    app->ed_account = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->ed_account), "e.g. alice@example.com");
    gtk_box_pack_start(GTK_BOX(form), labeled_row("Account:", app->ed_account, NULL), FALSE, FALSE, 0);

    GtkEntryBuffer *sbuf = secure_entry_buffer_new();
    app->ed_secret = gtk_entry_new_with_buffer(sbuf);
    g_object_unref(sbuf);
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->ed_secret), "base32 secret");
    gtk_box_pack_start(GTK_BOX(form), labeled_row("Secret:", app->ed_secret, NULL), FALSE, FALSE, 0);

    app->ed_algo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->ed_algo), "0", "SHA1");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->ed_algo), "1", "SHA256");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->ed_algo), "2", "SHA512");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->ed_algo), "0");
    gtk_box_pack_start(GTK_BOX(form), labeled_row("Algorithm:", app->ed_algo, NULL), FALSE, FALSE, 0);

    app->ed_digits = gtk_spin_button_new_with_range(6, 10, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->ed_digits), 6);
    gtk_box_pack_start(GTK_BOX(form), labeled_row("Digits:", app->ed_digits, NULL), FALSE, FALSE, 0);
    app->ed_period = gtk_spin_button_new_with_range(10, 300, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->ed_period), 30);
    gtk_box_pack_start(GTK_BOX(form), labeled_row("Period (s):", app->ed_period, NULL), FALSE, FALSE, 0);

    GtkWidget *ebtns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *addb = gtk_button_new_with_label("ADD ACCOUNT");
    add_class(addb, "action-button");
    gtk_widget_set_hexpand(addb, TRUE);
    g_signal_connect(addb, "clicked", G_CALLBACK(on_add_account), app);
    GtkWidget *delb = gtk_button_new_with_label("Delete selected");
    add_class(delb, "danger-button");
    g_signal_connect(delb, "clicked", G_CALLBACK(on_delete_account), app);
    gtk_box_pack_start(GTK_BOX(ebtns), addb, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(ebtns), delb, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(form), ebtns, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(form), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 4);
    GtkWidget *usec = gtk_label_new("\xE2\x9C\xA6 IMPORT otpauth:// URI");
    gtk_label_set_xalign(GTK_LABEL(usec), 0.0);
    add_class(usec, "section");
    gtk_box_pack_start(GTK_BOX(form), usec, FALSE, FALSE, 0);
    app->ed_uri = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->ed_uri), "otpauth://totp/Issuer:account?secret=...");
    GtkWidget *uapply = gtk_button_new_with_label("Import");
    g_signal_connect(uapply, "clicked", G_CALLBACK(on_uri_apply), app);
    gtk_box_pack_start(GTK_BOX(form), labeled_row("URI:", app->ed_uri, uapply), FALSE, FALSE, 0);

    gtk_paned_pack2(GTK_PANED(paned), form, TRUE, FALSE);

    /* footer */
    app->vw_meta = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(app->vw_meta), 0.0);
    add_class(app->vw_meta, "subtitle");
    gtk_box_pack_start(GTK_BOX(root), app->vw_meta, FALSE, FALSE, 0);
    app->vw_status = gtk_label_new("Ready.");
    gtk_label_set_xalign(GTK_LABEL(app->vw_status), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(app->vw_status), TRUE);
    gtk_box_pack_start(GTK_BOX(root), app->vw_status, FALSE, FALSE, 0);

    return root;
}

static void update_window_title(App *app) {
    const char *base = app->vault_path ? strrchr(app->vault_path, '/') : NULL;
    base = base ? base + 1 : (app->vault_path ? app->vault_path : "vault");
    char *t = g_strdup_printf("PQOTP \xE2\x80\x94 %s%s", base, app->dirty ? " *" : "");
    gtk_window_set_title(GTK_WINDOW(app->window), t);
    g_free(t);
}

static void set_dirty(App *app, gboolean dirty) {
    app->dirty = dirty;
    const char *cur = gtk_stack_get_visible_child_name(GTK_STACK(app->stack));
    if (cur && strcmp(cur, "vault") == 0) update_window_title(app);
}

static void show_vault_view(App *app) {
    clear_editor(app);
    refresh_store(app);

    const char *cipher = otp_vault_cipher(app->vault) == VAULT_CIPHER_AES_256_GCM
                         ? "AES-256-GCM" : "XChaCha20-Poly1305";
    const char *kdf = otp_vault_kdf(app->vault) == VAULT_KDF_BASIC ? "Argon2id Basic"
                    : otp_vault_kdf(app->vault) == VAULT_KDF_STRONG ? "Argon2id Strong"
                    : "Argon2id Medium";
    char meta[256];
    g_snprintf(meta, sizeof(meta), "%s  \xC2\xB7  %s  \xC2\xB7  %s  \xC2\xB7  %zu accounts",
               cipher, kdf,
               otp_vault_is_hybrid(app->vault) ? "Hybrid PQC: Kyber-1024 + X448"
                                               : "Classical (no PQC)",
               otp_vault_count(app->vault));
    gtk_label_set_text(GTK_LABEL(app->vw_meta), meta);

    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "vault");
    update_window_title(app);
    gtk_widget_show_all(app->stack);

    if (app->tick_id == 0)
        app->tick_id = g_timeout_add_seconds(1, tick_cb, app);
}

/* ----- about ------------------------------------------------------------ */

static void on_about(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const char *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    const char *comments =
        "PQOTP is a post-quantum two-factor (TOTP/HOTP) authenticator.\n\n"
        "\xE2\x80\xA2 RFC 6238 / RFC 4226 codes (SHA-1/256/512, 6\xE2\x80\x93" "10 digits)\n"
        "\xE2\x80\xA2 OTP secrets stored in a vault encrypted with AES-256-GCM\n"
        "  or XChaCha20-Poly1305, master key from Argon2id\n"
        "\xE2\x80\xA2 Optional post-quantum hybrid KEM (Kyber-1024 + X448)\n"
        "\xE2\x80\xA2 Secrets kept in locked, non-dumpable memory and never swapped;\n"
        "  the clipboard auto-clears after copying a code\n"
        "\xE2\x80\xA2 Companion to PQPMan";
    GtkWidget *d = gtk_about_dialog_new();
    GtkAboutDialog *ad = GTK_ABOUT_DIALOG(d);
    gtk_about_dialog_set_program_name(ad, "PQOTP");
    gtk_about_dialog_set_version(ad, PQOTP_VERSION);
    gtk_about_dialog_set_comments(ad, comments);
    gtk_about_dialog_set_authors(ad, authors);
    gtk_about_dialog_set_copyright(ad, "© 2026 Jean-Francois Lachance-Caumartin");
    gtk_about_dialog_set_license_type(ad, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_logo_icon_name(ad, "pqotp");
    gtk_window_set_transient_for(GTK_WINDOW(d), GTK_WINDOW(app->window));
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* ----- window lifecycle ------------------------------------------------- */

static gboolean on_window_delete(GtkWidget *w, GdkEvent *e, gpointer user) {
    (void)w; (void)e;
    App *app = user;
    if (app->vault && app->dirty &&
        !confirm_dialog(app, "You have unsaved changes. Quit anyway and discard them?"))
        return TRUE;
    return FALSE;
}

static void on_window_destroy(GtkWidget *w, gpointer user) {
    (void)w;
    App *app = user;
    app->window_gone = 1;
    if (app->tick_id) { g_source_remove(app->tick_id); app->tick_id = 0; }
    if (app->current_job) return;   /* worker owns teardown */
    if (app->vault) { otp_vault_free(app->vault); app->vault = NULL; }
    if (app->master) sodium_free(app->master);
    g_free(app->vault_path);
    g_free(app);
}

static void load_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(p), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

static void activate(GtkApplication *gapp, gpointer user) {
    (void)user;
    App *app = g_new0(App, 1);
    app->gapp = gapp;
    app->master = sodium_malloc(PASSWORD_MAX);
    if (app->master) sodium_memzero(app->master, PASSWORD_MAX);

    load_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "PQOTP \xE2\x80\x94 locked");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 880, 560);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "pqotp");
    gtk_window_set_position(GTK_WINDOW(app->window), GTK_WIN_POS_CENTER);

    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    GtkWidget *title = gtk_label_new("PQOTP  \xC2\xB7  POST-QUANTUM AUTHENTICATOR");
    add_class(title, "hb-title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title);
    GtkWidget *about = gtk_button_new_with_label("About");
    g_signal_connect(about, "clicked", G_CALLBACK(on_about), app);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), about);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hb);

    app->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app->stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_add_named(GTK_STACK(app->stack), build_lock_view(app), "lock");
    gtk_stack_add_named(GTK_STACK(app->stack), build_vault_view(app), "vault");

    GtkWidget *scroller = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroller), app->stack);
    gtk_container_add(GTK_CONTAINER(app->window), scroller);

    gtk_window_set_default(GTK_WINDOW(app->window), app->lk_button);

    g_signal_connect(app->window, "delete-event", G_CALLBACK(on_window_delete), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), app);

    gtk_widget_show_all(app->window);
    gtk_stack_set_visible_child_name(GTK_STACK(app->stack), "lock");
    gtk_widget_set_visible(app->lk_create_box, FALSE);
    gtk_widget_set_visible(app->lk_confirm_row, FALSE);
}

int main(int argc, char **argv) {
    if (otp_vault_init() != 0) {
        g_printerr("Failed to initialise crypto library.\n");
        return 1;
    }
    GtkApplication *gapp = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
