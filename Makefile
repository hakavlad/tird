NAME = tird
DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
MANDIR ?=  $(DATADIR)/man

PANDOC := $(shell command -v pandoc 2> /dev/null)

all:
	@echo "Use: make install, make uninstall, make build-deb, make install-deb, make manpage"

install:
	install -p -d $(DESTDIR)$(BINDIR)
	install -p -m0755 src/$(NAME)/$(NAME).py $(DESTDIR)$(BINDIR)/$(NAME)

	install -p -d $(DESTDIR)$(MANDIR)/man1
	gzip -9cn docs/$(NAME).1 > $(DESTDIR)$(MANDIR)/man1/$(NAME).1.gz

uninstall:
	rm -fv $(DESTDIR)$(BINDIR)/$(NAME)
	rm -fv $(DESTDIR)$(MANDIR)/man1/$(NAME).1.gz

build-deb:
	install -p -d dist/build/$(NAME)/usr/bin
	install -p -m0755 src/$(NAME)/$(NAME).py dist/build/$(NAME)/usr/bin/$(NAME)

	install -p -d dist/build/$(NAME)/usr/share/man/man1
	gzip -9cn docs/$(NAME).1 > dist/build/$(NAME)/usr/share/man/man1/$(NAME).1.gz

	install -p -d dist/build/$(NAME)/usr/share/doc/$(NAME)
	install -p -m0644 README.md dist/build/$(NAME)/usr/share/doc/$(NAME)/README.md
	install -p -m0644 SECURITY.md dist/build/$(NAME)/usr/share/doc/$(NAME)/SECURITY.md
	install -p -m0644 docs/MANPAGE.md dist/build/$(NAME)/usr/share/doc/$(NAME)/MANPAGE.md
	install -p -m0644 docs/SPECIFICATION.md dist/build/$(NAME)/usr/share/doc/$(NAME)/SPECIFICATION.md
	install -p -m0644 images/$(NAME).ico dist/build/$(NAME)/usr/share/doc/$(NAME)/$(NAME).ico

	cp -r dist/DEBIAN dist/build/$(NAME)/
	fakeroot dpkg-deb --build dist/build/$(NAME)
	##  Now you can run
	##  sudo make install-deb

install-deb:
	apt install -o Acquire::AllowUnsizedPackages=1 --reinstall ./dist/build/$(NAME).deb

manpage:
ifdef PANDOC
	pandoc docs/MANPAGE.md -s -t man > docs/$(NAME).1
	man ./docs/$(NAME).1
else
	@echo "pandoc is not installed, skipping manpage generation"
endif
