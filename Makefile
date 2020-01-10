#
# Copyright (C) 2014-2020 Canonical, Ltd.
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

VERSION=0.02.12
#
# Version "Perspicacious Process Peeker"
#

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' -O2 -g
#
# Pedantic flags
#
ifeq ($(PEDANTIC),1)
CFLAGS += -Wabi -Wcast-qual -Wfloat-equal -Wmissing-declarations \
	-Wmissing-format-attribute -Wno-long-long -Wpacked \
	-Wredundant-decls -Wshadow -Wno-missing-field-initializers \
	-Wno-missing-braces -Wno-sign-compare -Wno-multichar
endif

export DEB_BUILD_HARDENING=1

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

forkstat: forkstat.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS)

forkstat.8.gz: forkstat.8
	gzip -c $< > $@

.PHONEY: dist
dist:
	rm -rf forkstat-$(VERSION)
	mkdir forkstat-$(VERSION)
	cp -rp Makefile forkstat.c forkstat.8 mascot COPYING \
		snap .travis.yml forkstat-$(VERSION)
	tar -Jcf forkstat-$(VERSION).tar.xz forkstat-$(VERSION)
	rm -rf forkstat-$(VERSION)

.PHONEY: pdf
pdf:
	man -t ./forkstat.8 | ps2pdf - > forkstat.pdf

.PHONEY: clean
clean:
	rm -f forkstat forkstat.o forkstat.8.gz
	rm -f forkstat-$(VERSION).tar.xz
	rm -f forkstat.pdf

.PHONEY: install
install: forkstat forkstat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp forkstat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp forkstat.8.gz ${DESTDIR}${MANDIR}
