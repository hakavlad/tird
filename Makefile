NAME = tird
DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

all:
	@ echo "Use: make install, make uninstall, make manpage, make build-deb, make install-deb"

install:
	install -p -d $(DESTDIR)$(BINDIR)
	install -p -m0755 $(NAME)/$(NAME).py $(DESTDIR)$(BINDIR)/$(NAME)

uninstall:
	rm -fv $(DESTDIR)$(BINDIR)/$(NAME)

manpage:
	pandoc docs/MANPAGE.md -s -t man > docs/$(NAME).1
	man ./docs/$(NAME).1

build-deb:
	install -p -d deb/$(NAME)
	install -p -d deb/$(NAME)/usr/bin
	install -p -m0755 $(NAME)/$(NAME).py deb/$(NAME)/usr/bin/$(NAME)
	cp -r deb/DEBIAN deb/$(NAME)/
	fakeroot dpkg-deb --build deb/$(NAME)

install-deb:
	apt install -o Acquire::AllowUnsizedPackages=1 --reinstall ./deb/$(NAME).deb
