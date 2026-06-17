# Makefile for PQOTP - post-quantum TOTP/HOTP authenticator.
#
#   make                build ./pqotp-gui (GTK3 app) and ./pqotp (CLI)
#   sudo make install   install globally (binaries, icons, menu entry)
#   sudo make uninstall remove all installed files
#   make clean          remove build artifacts

VERSION := 0.1.1
GUI      := pqotp-gui
CLI      := pqotp

PREFIX   ?= /usr/local
BINDIR   := $(PREFIX)/bin
DATADIR  := $(PREFIX)/share
APPDIR   := $(DATADIR)/applications
ICONBASE := $(DATADIR)/icons/hicolor
ICONDIR  := $(ICONBASE)/scalable/apps

# Raster icon sizes installed alongside the scalable SVG so the icon shows
# reliably in the applications menu and the window/taskbar.
ICON_SIZES := 16 24 32 48 64 128 256

CC      ?= cc
GUI_PKGS = gtk+-3.0 libsodium libargon2 libcrypto
CLI_PKGS = libsodium libargon2 libcrypto
CFLAGS  ?= -O2 -Wall -Wextra
# Kyber-1024 = NIST level 5 (KYBER_K=4); kyber/ holds the CRYSTALS reference.
CFLAGS  += -DPQOTP_VERSION=\"$(VERSION)\" -DKYBER_K=4 -Isrc/kyber

# Kyber-1024 reference sources (SHAKE/fips202 only). randombytes is resolved
# from libsodium, so kyber/randombytes.c is intentionally omitted.
KYBER_SRC = src/kyber/kem.c src/kyber/indcpa.c src/kyber/poly.c \
            src/kyber/polyvec.c src/kyber/ntt.c src/kyber/reduce.c \
            src/kyber/cbd.c src/kyber/fips202.c src/kyber/verify.c \
            src/kyber/symmetric-shake.c

# Shared crypto/OTP core (no GTK).
CORE_SRC = src/otp_vault.c src/totp.c src/hybrid_kem.c $(KYBER_SRC)
CORE_OBJ = $(CORE_SRC:.c=.o)

GUI_SRC  = src/gui.c src/secure_buffer.c
GUI_OBJ  = $(GUI_SRC:.c=.o)
CLI_OBJ  = src/cli.o

GUI_CFLAGS = $(shell pkg-config --cflags $(GUI_PKGS))
GUI_LIBS   = $(shell pkg-config --libs $(GUI_PKGS)) -lm
CLI_CFLAGS = $(shell pkg-config --cflags $(CLI_PKGS))
CLI_LIBS   = $(shell pkg-config --libs $(CLI_PKGS)) -lm

.PHONY: all clean install uninstall

all: $(GUI) $(CLI)

# Core objects are GTK-free; compile with plain CFLAGS.
$(CORE_OBJ): src/%.o: src/%.c
	$(CC) $(CFLAGS) $(CLI_CFLAGS) -c $< -o $@

src/gui.o: src/gui.c
	$(CC) $(CFLAGS) $(GUI_CFLAGS) -c $< -o $@
src/secure_buffer.o: src/secure_buffer.c
	$(CC) $(CFLAGS) $(GUI_CFLAGS) -c $< -o $@
src/cli.o: src/cli.c
	$(CC) $(CFLAGS) $(CLI_CFLAGS) -c $< -o $@

$(GUI): $(GUI_OBJ) $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $(GUI_OBJ) $(CORE_OBJ) $(GUI_LIBS)

$(CLI): $(CLI_OBJ) $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $(CLI_OBJ) $(CORE_OBJ) $(CLI_LIBS)

clean:
	rm -f $(GUI_OBJ) $(CLI_OBJ) $(CORE_OBJ) $(GUI) $(CLI)

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(GUI) $(DESTDIR)$(BINDIR)/$(GUI)
	install -m 0755 $(CLI) $(DESTDIR)$(BINDIR)/$(CLI)
	install -d $(DESTDIR)$(ICONDIR)
	install -m 0644 data/pqotp.svg $(DESTDIR)$(ICONDIR)/pqotp.svg
	for s in $(ICON_SIZES); do \
	    install -d $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps; \
	    install -m 0644 data/pqotp-$${s}.png \
	        $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps/pqotp.png; \
	done
	install -d $(DESTDIR)$(APPDIR)
	install -m 0644 data/pqotp.desktop $(DESTDIR)$(APPDIR)/pqotp.desktop
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "PQOTP $(VERSION) installed to $(BINDIR)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(GUI)
	rm -f $(DESTDIR)$(BINDIR)/$(CLI)
	rm -f $(DESTDIR)$(ICONDIR)/pqotp.svg
	for s in $(ICON_SIZES); do \
	    rm -f $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps/pqotp.png; \
	done
	rm -f $(DESTDIR)$(APPDIR)/pqotp.desktop
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "PQOTP uninstalled"
