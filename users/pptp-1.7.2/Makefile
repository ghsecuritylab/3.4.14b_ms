# $Id: Makefile,v 1.47 2008/05/14 06:32:52 quozl Exp $
VERSION=1.7.2
RELEASE=

KERNEL_VER=$(patsubst $(DIR_ROOT)/%,%,$(DIR_LINUX))

ifeq ($(KERNEL_VER),linux-2.6.30)
include ../../linux-2.6.30/.config
endif
ifeq ($(KERNEL_VER),linux-3.10)
include ../../linux-3.10/.config
endif

#################################################################
# CHANGE THIS LINE to point to the location of your pppd binary.
PPPD = /usr/sbin/pppd
#################################################################

BINDIR=$(DESTDIR)/usr/sbin
MANDIR=$(DESTDIR)/usr/share/man/man8
PPPDIR=$(DESTDIR)/etc/ppp

#CC	= gcc
RM	= rm -f
OPTIMIZE= -Os
DEBUG	= -g
INCLUDE =
#CFLAGS  = -Wall $(OPTIMIZE) $(DEBUG) $(INCLUDE)
CFLAGS  += -Wall $(OPTIMIZE) $(INCLUDE) -DNO_LD_SHARELIB #-ffunction-sections -fdata-sections
CFLAGS += $(EXTRA_CFLAGS)

ifeq ($(CONFIG_RTL_PPTP_CTL_DIRECT_REPLY), y)
CFLAGS	+= -DCONFIG_KERNEL_DIRECT_REPLY
endif
#LIBS	= -lutil
# Solaris 10
# LIBS	= -lnsl -lsocket -lresolv
# Solaris Nevada build 14 or above
# LIBS    = -lnsl -lsocket
LDFLAGS	=

PPTP_BIN = pptp

PPTP_OBJS = pptp.o pptp_gre.o ppp_fcs.o \
            pptp_ctrl.o dirutil.o vector.o \
	    inststr.o util.o version.o test.o \
	    pptp_quirks.o orckit_quirks.o pqueue.o pptp_callmgr.o routing.o \
	    pptp_compat.o

PPTP_DEPS = pptp_callmgr.h pptp_gre.h ppp_fcs.h util.h test.h \
	    pptp_quirks.h orckit_quirks.h config.h pqueue.h routing.h

all: config.h $(PPTP_BIN) pptpsetup.8

$(PPTP_BIN): $(PPTP_OBJS) $(PPTP_DEPS)
	$(CC) $(CFLAGS) -o $(PPTP_BIN) $(PPTP_OBJS) $(LDFLAGS) $(LIBS)
	$(STRIP) $@

POD2MAN_EXIST := $(shell which pod2man; if [ $$? -eq 1 ]; then echo 0; else echo 1; fi;)
pptpsetup.8: pptpsetup
	if [ $(POD2MAN_EXIST) -eq 1 ];\
	then pod2man $? > $@ ; \
	else echo "no pod2man"; \
	fi;

config.h: 
	echo "/* text added by Makefile target config.h */" > config.h
	echo "#define PPTP_LINUX_VERSION \"$(VERSION)$(RELEASE)\"" >> config.h
	echo "#define PPPD_BINARY \"$(PPPD)\"" >> config.h

vector_test: vector_test.o vector.o
	$(CC) -o vector_test vector_test.o vector.o

clean:
	$(RM)  $(PPTP_BIN) *.o config.h

clobber: clean
	$(RM) $(PPTP_BIN) vector_test

distclean: clobber

test: vector_test

install:
	mkdir -p $(BINDIR)
	install -o root -m 555 pptp $(BINDIR)
	install -o root -m 555 pptpsetup $(BINDIR)
	mkdir -p $(MANDIR)
	install -m 644 pptp.8 $(MANDIR)
	install -m 644 pptpsetup.8 $(MANDIR)
	mkdir -p $(PPPDIR)
	install -m 644 options.pptp $(PPPDIR)

uninstall:
	$(RM) $(BINDIR)/pptp $(MANDIR)/pptp.8

dist: clobber
	$(RM) pptp-$(VERSION)$(RELEASE).tar.gz
	$(RM) -r pptp-$(VERSION)
	mkdir pptp-$(VERSION)
	cp --recursive ChangeLog Makefile *.c *.h options.pptp pptp.8 \
		pptpsetup Documentation AUTHORS COPYING INSTALL NEWS \
		README DEVELOPERS TODO USING PROTOCOL-SECURITY \
		pptp-$(VERSION)/
	$(RM) -r pptp-$(VERSION)/CVS pptp-$(VERSION)/*/CVS
	tar czf pptp-$(VERSION)$(RELEASE).tar.gz pptp-$(VERSION)
	$(RM) -r pptp-$(VERSION)
	md5sum pptp-$(VERSION)$(RELEASE).tar.gz

deb:
	chmod +x debian/rules 
	fakeroot dpkg-buildpackage -us -uc
	mv ../pptp_$(VERSION)-0_i386.deb .

WEB=~/public_html/external/mine/pptp/pptpconfig
release:
	cp pptp_$(VERSION)-0_i386.deb $(WEB)
	cd $(WEB);make

romfs:
	$(ROMFSINST) /bin/$(PPTP_BIN)

