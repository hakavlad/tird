NAME = tird
DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

all:
	@ echo "Use: make install, make uninstall, make manpage"

install:
	install -p -d $(DESTDIR)$(BINDIR)
	install -p -m0755 $(NAME)/$(NAME).py $(DESTDIR)$(BINDIR)/$(NAME)

uninstall:
	rm -fv $(DESTDIR)$(BINDIR)/$(NAME)

manpage:
	pandoc docs/MANPAGE.md -s -t man > docs/$(NAME).1
	man ./docs/$(NAME).1
