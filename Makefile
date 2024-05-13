NAME = tird
DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
MANDIR ?=  $(DATADIR)/man

PANDOC := $(shell command -v pandoc 2> /dev/null)

all:
	@ echo "Use: make install, make uninstall, make build-deb, make install-deb, make manpage"

install:
	install -p -d $(DESTDIR)$(BINDIR)
	install -p -m0755 $(NAME)/$(NAME).py $(DESTDIR)$(BINDIR)/$(NAME)

uninstall:
	rm -fv $(DESTDIR)$(BINDIR)/$(NAME)

build-deb:
	install -p -d deb/$(NAME)/usr/bin
	install -p -m0755 $(NAME)/$(NAME).py deb/$(NAME)/usr/bin/$(NAME)
	install -p -d deb/$(NAME)/usr/share/man/man1
	gzip -9cn docs/$(NAME).1 > deb/$(NAME)/usr/share/man/man1/$(NAME).1.gz
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
