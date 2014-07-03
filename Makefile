VERSION=0.01.08
#
# Version "Frantic Forking Finder"
#

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"'

export DEB_BUILD_HARDENING=1

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

forkstat: forkstat.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS)

forkstat.8.gz: forkstat.8
	gzip -c $< > $@

dist:
	rm -rf forkstat-$(VERSION)
	mkdir forkstat-$(VERSION)
	cp Makefile forkstat.c forkstat.8 forkstat-$(VERSION)
	tar -zcf forkstat-$(VERSION).tar.gz forkstat-$(VERSION)
	rm -rf forkstat-$(VERSION)

clean:
	rm -f forkstat forkstat.o forkstat.8.gz
	rm -f forkstat-$(VERSION).tar.gz

install: forkstat forkstat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp forkstat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp forkstat.8.gz ${DESTDIR}${MANDIR}
