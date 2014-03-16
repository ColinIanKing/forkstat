VERSION=0.01.00
#
# Version "Deep Piercing Eyes"
#

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"'

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

forkstat: forkstat.o
	$(CC) $(CFLAGS) $< -lm -o $@ $(LDFLAGS)

forkstat.8.gz: forkstat.8
	gzip -c $< > $@

dist:
	git archive --format=tar --prefix="forkstat-$(VERSION)/" V$(VERSION) | \
		gzip > forkstat-$(VERSION).tar.gz

clean:
	rm -f forkstat forkstat.o forkstat.8.gz
	rm -f forkstat-$(VERSION).tar.gz

install: forkstat forkstat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp forkstat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp forkstat.8.gz ${DESTDIR}${MANDIR}
