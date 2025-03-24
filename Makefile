NAME = tird

DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
MANDIR ?=  $(DATADIR)/man

DEB_USR = distribution/build/$(NAME)/usr

PANDOC := $(shell command -v pandoc 2> /dev/null)

all:
	@echo "Use: make install, make uninstall, make build-deb, make install-deb, make clean, make manpage"

install:
	@echo "Installing $(NAME)..."
	install -p -d $(DESTDIR)$(BINDIR)
	install -p -m0755 src/$(NAME)/$(NAME).py $(DESTDIR)$(BINDIR)/$(NAME)

	install -p -d $(DESTDIR)$(MANDIR)/man1
	gzip -9cn docs/$(NAME).1 > $(DESTDIR)$(MANDIR)/man1/$(NAME).1.gz
	@echo "$(NAME) installed successfully."

uninstall:
	@echo "Uninstalling $(NAME)..."
	rm -fv $(DESTDIR)$(BINDIR)/$(NAME)
	rm -fv $(DESTDIR)$(MANDIR)/man1/$(NAME).1.gz
	@echo "$(NAME) uninstalled successfully."

build-deb:
	@echo "Building Debian package for $(NAME)..."
	install -p -d $(DEB_USR)/bin
	install -p -m0755 src/$(NAME)/$(NAME).py $(DEB_USR)/bin/$(NAME)

	install -p -d $(DEB_USR)/share/man/man1
	gzip -9cn docs/$(NAME).1 > $(DEB_USR)/share/man/man1/$(NAME).1.gz

	install -p -d $(DEB_USR)/share/doc/$(NAME)
	install -p -m0644 README.md $(DEB_USR)/share/doc/$(NAME)/README.md
	install -p -m0644 SECURITY.md $(DEB_USR)/share/doc/$(NAME)/SECURITY.md
	tar -czf $(DEB_USR)/share/doc/$(NAME)/docs.tar.gz docs

	cp -r distribution/DEBIAN distribution/build/$(NAME)/
	fakeroot dpkg-deb --build distribution/build/$(NAME)
	@echo "Debian package built successfully."

install-deb:
	@echo "Installing Debian package..."
	apt install -o Acquire::AllowUnsizedPackages=1 --reinstall ./distribution/build/$(NAME).deb

clean:
	@echo "Cleaning up..."
	@if [ -d distribution/build/ ]; then \
		rm -rf distribution/build/; \
		echo "Removed distribution/build/"; \
	else \
		echo "Directory distribution/build/ does not exist."; \
	fi

manpage:
ifdef PANDOC
	@echo "Generating manpage..."
	pandoc docs/MANPAGE.md -s -t man > docs/$(NAME).1
	man ./docs/$(NAME).1
else
	@echo "pandoc is not installed, skipping manpage generation"
endif
