# Setuid launcher for the disposable login browser.
#
# Build:                   make
# Install (root, once):    make install            # default PREFIX=/usr/local/libexec/vela
#   or to a dedicated account UID (recommended):
#                          make install BROWSER_UID=<uid>
CC      ?= cc
PREFIX  ?= /usr/local/libexec/vela
BROWSER_UID ?= 65534

CFLAGS  ?= -O2 -Wall -Wextra
# Warnings are errors for a privileged program: a latent bug in something that
# runs setuid root is a privilege-escalation vector, not a style nit.
CFLAGS  += -Werror

SOURCES := vela-browser-sandbox.c
TARGET  := vela-browser-sandbox

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -DBROWSER_UID=$(BROWSER_UID) -o $@ $(SOURCES)

# One-time privileged install. Must be run as root. The binary is made setuid
# root: it drops to BROWSER_UID itself, and refuses to run otherwise.
install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/$(TARGET)
	chown root:root $(DESTDIR)$(PREFIX)/$(TARGET)
	chmod 4755 $(DESTDIR)$(PREFIX)/$(TARGET)
	@echo
	@echo "Installed setuid launcher at $(DESTDIR)$(PREFIX)/$(TARGET)"
	@echo "It will run the disposable browser as uid $(BROWSER_UID)."
	@echo
	@echo "To use it, point the app at it:"
	@echo "    VELA_BROWSER_SANDBOX=$(DESTDIR)$(PREFIX)/$(TARGET)"
	@echo "Recommended: create a dedicated unprivileged account first, e.g."
	@echo "    useradd -r -M -s /usr/sbin/nologin vela-browser"
	@echo "    make install BROWSER_UID=\$$(id -u vela-browser)"

clean:
	rm -f $(TARGET)

.PHONY: all install clean
