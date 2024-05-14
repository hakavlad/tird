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
	install -p -m0755 $(NAME)/$(NAME).py $(DESTDIR)$(BINDIR)/$(NAME)

	install -p -d $(DESTDIR)$(MANDIR)/man1
	gzip -9cn docs/$(NAME).1 > $(DESTDIR)$(MANDIR)/man1/$(NAME).1.gz

uninstall:
	rm -fv $(DESTDIR)$(BINDIR)/$(NAME)
	rm -fv $(DESTDIR)$(MANDIR)/man1/$(NAME).1.gz

build-deb:
	install -p -d deb/$(NAME)/usr/bin
	install -p -m0755 $(NAME)/$(NAME).py deb/$(NAME)/usr/bin/$(NAME)

	install -p -d deb/$(NAME)/usr/share/man/man1
	gzip -9cn docs/$(NAME).1 > deb/$(NAME)/usr/share/man/man1/$(NAME).1.gz

	install -p -d deb/$(NAME)/usr/share/doc/$(NAME)
	install -p -m0644 README.md deb/$(NAME)/usr/share/doc/$(NAME)/README.md
	install -p -m0644 SECURITY.md deb/$(NAME)/usr/share/doc/$(NAME)/SECURITY.md
	install -p -m0644 docs/MANPAGE.md deb/$(NAME)/usr/share/doc/$(NAME)/MANPAGE.md
	install -p -m0644 docs/SPECIFICATION.md deb/$(NAME)/usr/share/doc/$(NAME)/SPECIFICATION.md
	install -p -m0644 images/$(NAME).ico deb/$(NAME)/usr/share/doc/$(NAME)/$(NAME).ico

	cp -r deb/DEBIAN deb/$(NAME)/
	fakeroot dpkg-deb --build deb/$(NAME)
	##  Now you can run
	##  sudo make install-deb

install-deb:
	apt install -o Acquire::AllowUnsizedPackages=1 --reinstall ./deb/$(NAME).deb

manpage:
ifdef PANDOC
	pandoc docs/MANPAGE.md -s -t man > docs/$(NAME).1
	man ./docs/$(NAME).1
else
	@echo "pandoc is not installed, skipping manpage generation"
endif
