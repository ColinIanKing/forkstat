#
# Copyright (C) 2014-2015 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

VERSION=0.01.13
#
# Version "Frantic Forking Finder"
#

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' -O2

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
	cp -rp Makefile forkstat.c forkstat.8 mascot COPYING \
		forkstat-$(VERSION)
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
