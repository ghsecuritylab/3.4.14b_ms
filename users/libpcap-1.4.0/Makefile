
include $(DIR_LINUX)/.config
DIR_ROMFS = ../../target/romfs
ROMFSINST = ../../config/romfsinst

-include .config	#must included,  or romfsinst doesn't work 

# VPATH
srcdir = .

CCOPT = -O2 -fpic
INCLS = -I. 
DEFS = -DHAVE_CONFIG_H  -D_U_="__attribute__((unused))"
ADDLOBJS = 
ADDLARCHIVEOBJS = 
LIBS = 
CFLAGS = -g -O2
LDFLAGS = 
DYEXT = so
V_RPATH_OPT = -Wl,-rpath,
PROG=libpcap

# Standard CFLAGS
FULL_CFLAGS = $(CCOPT) $(INCLS) $(DEFS) $(CFLAGS)

#
# Flex and bison allow you to specify the prefixes of the global symbols
# used by the generated parser.  This allows programs to use lex/yacc
# and link against libpcap.  If you don't have flex or bison, get them.
#
LEX = flex -Ppcap_
YACC = bison -y -p pcap_

# Explicitly define compilation rule since SunOS 4's make doesn't like gcc.
# Also, gcc does not remove the .o before forking 'as', which can be a
# problem if you don't own the file but can write to the directory.
.c.o:
	@rm -f $@
	$(CC) $(FULL_CFLAGS) -c $(srcdir)/$*.c

PSRC =	pcap-linux.c pcap-usb-linux.c    
FSRC =  fad-getad.c	
SSRC =  
CSRC =	pcap.c inet.c gencode.c optimize.c nametoaddr.c etherent.c \
		savefile.c sf-pcap.c sf-pcap-ng.c pcap-common.c \
		bpf_image.c bpf_dump.c
GENSRC = scanner.c grammar.c bpf_filter.c version.c
LIBOBJS = 

SRC =	$(PSRC) $(FSRC) $(CSRC) $(SSRC) $(GENSRC)

# We would like to say "OBJ = $(SRC:.c=.o)" but Ultrix's make cannot
# hack the extra indirection
OBJ =	$(PSRC:.c=.o) $(FSRC:.c=.o) $(CSRC:.c=.o) $(SSRC:.c=.o) $(GENSRC:.c=.o) $(LIBOBJS)
PUBHDR = \
	pcap.h \
	pcap-bpf.h \
	pcap-namedb.h \
	pcap/bpf.h \
	pcap/bluetooth.h \
	pcap/ipnet.h \
	pcap/namedb.h \
	pcap/pcap.h \
	pcap/sll.h \
	pcap/vlan.h \
	pcap/usb.h

HDR = $(PUBHDR) \
	arcnet.h \
	atmuni31.h \
	ethertype.h \
	gencode.h \
	ieee80211.h \
	llc.h \
	nlpid.h \
	pcap-common.h \
	pcap-int.h \
	pcap-stdinc.h \
	ppp.h \
	sf-pcap.h \
	sf-pcap-ng.h \
	sunatmpos.h



GENHDR = \
	scanner.h tokdefs.h version.h

TAGFILES = \
	$(SRC) $(HDR)

CLEANFILES = $(OBJ) libpcap.* $(TESTS) \
	$(PROG)-`cat $(srcdir)/VERSION`.tar.gz $(GENSRC) $(GENHDR) \
	lex.yy.c pcap-config

MAN1 = pcap-config.1

MAN3PCAP_EXPAND = \
	pcap.3pcap.in \
	pcap_compile.3pcap.in \
	pcap_datalink.3pcap.in \
	pcap_dump_open.3pcap.in \
	pcap_list_datalinks.3pcap.in \
	pcap_list_tstamp_types.3pcap.in \
	pcap_open_dead.3pcap.in \
	pcap_open_offline.3pcap.in \
	pcap_set_tstamp_type.3pcap.in

MAN3PCAP_NOEXPAND = \
	pcap_activate.3pcap \
	pcap_breakloop.3pcap \
	pcap_can_set_rfmon.3pcap \
	pcap_close.3pcap \
	pcap_create.3pcap \
	pcap_datalink_name_to_val.3pcap \
	pcap_datalink_val_to_name.3pcap \
	pcap_dump.3pcap \
	pcap_dump_close.3pcap \
	pcap_dump_file.3pcap \
	pcap_dump_flush.3pcap \
	pcap_dump_ftell.3pcap \
	pcap_file.3pcap \
	pcap_fileno.3pcap \
	pcap_findalldevs.3pcap \
	pcap_freecode.3pcap \
	pcap_get_selectable_fd.3pcap \
	pcap_geterr.3pcap \
	pcap_inject.3pcap \
	pcap_is_swapped.3pcap \
	pcap_lib_version.3pcap \
	pcap_lookupdev.3pcap \
	pcap_lookupnet.3pcap \
	pcap_loop.3pcap \
	pcap_major_version.3pcap \
	pcap_next_ex.3pcap \
	pcap_offline_filter.3pcap \
	pcap_open_live.3pcap \
	pcap_set_buffer_size.3pcap \
	pcap_set_datalink.3pcap \
	pcap_set_promisc.3pcap \
	pcap_set_rfmon.3pcap \
	pcap_set_snaplen.3pcap \
	pcap_set_timeout.3pcap \
	pcap_setdirection.3pcap \
	pcap_setfilter.3pcap \
	pcap_setnonblock.3pcap \
	pcap_snapshot.3pcap \
	pcap_stats.3pcap \
	pcap_statustostr.3pcap \
	pcap_strerror.3pcap \
	pcap_tstamp_type_name_to_val.3pcap \
	pcap_tstamp_type_val_to_name.3pcap

MAN3PCAP = $(MAN3PCAP_NOEXPAND) $(MAN3PCAP_EXPAND:.in=)

MANFILE = \
	pcap-savefile.manfile.in

MANMISC = \
	pcap-filter.manmisc.in \
	pcap-linktype.manmisc.in \
	pcap-tstamp.manmisc.in

EXTRA_DIST = \
	$(TESTS_SRC) \
	CHANGES \
	ChmodBPF/ChmodBPF \
	ChmodBPF/StartupParameters.plist \
	CREDITS \
	INSTALL.txt \
	LICENSE \
	Makefile.in \
	README \
	README.aix \
	README.dag \
	README.hpux \
	README.linux \
	README.macosx \
	README.septel \
	README.sita \
	README.tru64 \
	README.Win32 \
	SUNOS4/nit_if.o.sparc \
	SUNOS4/nit_if.o.sun3 \
	SUNOS4/nit_if.o.sun4c.4.0.3c \
	TODO \
	VERSION \
	aclocal.m4 \
	bpf/net/bpf_filter.c \
	chmod_bpf \
	config.guess \
	config.h.in \
	config.sub \
	configure \
	configure.in \
	dlpisubs.c \
	dlpisubs.h \
	fad-getad.c \
	fad-gifc.c \
	fad-glifc.c \
	fad-null.c \
	fad-sita.c \
	fad-win32.c \
	grammar.y \
	install-sh \
	lbl/os-aix4.h \
	lbl/os-hpux11.h \
	lbl/os-osf4.h \
	lbl/os-osf5.h \
	lbl/os-solaris2.h \
	lbl/os-sunos4.h \
	lbl/os-ultrix4.h \
	missing/snprintf.c \
	mkdep \
	msdos/bin2c.c \
	msdos/common.dj \
	msdos/makefile \
	msdos/makefile.dj \
	msdos/makefile.wc \
	msdos/ndis2.c \
	msdos/ndis2.h \
	msdos/ndis_0.asm \
	msdos/pkt_rx0.asm \
	msdos/pkt_rx1.s \
	msdos/pktdrvr.c \
	msdos/pktdrvr.h \
	msdos/readme.dos \
	org.tcpdump.chmod_bpf.plist \
	packaging/pcap.spec.in \
	pcap-bpf.c \
	pcap-bt-linux.c \
	pcap-bt-linux.h \
	pcap-can-linux.c \
	pcap-can-linux.h \
	pcap-canusb-linux.c \
	pcap-canusb-linux.h \
	pcap-config.in \
	pcap-dag.c \
	pcap-dag.h \
	pcap-dlpi.c \
	pcap-dos.c \
	pcap-dos.h \
	pcap-enet.c \
	pcap-int.h \
	pcap-libdlpi.c \
	pcap-linux.c \
	pcap-namedb.h \
	pcap-netfilter-linux.c \
	pcap-netfilter-linux.h \
	pcap-nit.c \
	pcap-null.c \
	pcap-pf.c \
	pcap-septel.c \
	pcap-septel.h \
	pcap-sita.h \
	pcap-sita.c \
	pcap-sita.html \
	pcap-snf.c \
	pcap-snf.h \
	pcap-snit.c \
	pcap-snoop.c \
	pcap-usb-linux.c \
	pcap-usb-linux.h \
	pcap-win32.c \
	runlex.sh \
	scanner.l \
	Win32/Include/Gnuc.h \
	Win32/Include/addrinfo.h \
	Win32/Include/bittypes.h \
	Win32/Include/cdecl_ext.h \
	Win32/Include/inetprivate.h \
	Win32/Include/ip6_misc.h \
	Win32/Include/sockstorage.h \
	Win32/Include/arpa/nameser.h \
	Win32/Include/net/if.h \
	Win32/Include/net/netdb.h \
	Win32/Include/net/paths.h \
	Win32/Prj/libpcap.dsp \
	Win32/Prj/libpcap.dsw \
	Win32/Src/ffs.c \
	Win32/Src/gai_strerror.c \
	Win32/Src/getaddrinfo.c \
	Win32/Src/getnetbynm.c \
	Win32/Src/getnetent.c \
	Win32/Src/getopt.c \
	Win32/Src/getservent.c \
	Win32/Src/inet_aton.c \
	Win32/Src/inet_net.c \
	Win32/Src/inet_pton.c

all: libpcap.a shared 

libpcap.a: $(OBJ)
	@rm -f $@
	$(AR) rc $@ $(OBJ) $(ADDLARCHIVEOBJS)
	$(RANLIB) $@

shared: libpcap.$(DYEXT)

libpcap.so: $(OBJ)
	@rm -f $@
	VER=`cat $(srcdir)/VERSION`; \
	MAJOR_VER=`sed 's/\([0-9][0-9]*\)\..*/\1/' $(srcdir)/VERSION`; \
	$(CC) -shared -Wl,-soname,$@.$$MAJOR_VER $(LDFLAGS) \
	    -o $@.$$VER $(OBJ) $(ADDLOBJS) $(LIBS)

#
# For platforms that don't support shared libraries (or on which we
# don't support shared libraries).
#
libpcap.none:

scanner.c: $(srcdir)/scanner.l
	@rm -f $@
	chmod u+x $(srcdir)/runlex.sh
	$(srcdir)/runlex.sh $(LEX) -o$@ $<

scanner.o: scanner.c tokdefs.h
	$(CC) $(FULL_CFLAGS) -c scanner.c

pcap.o: version.h

tokdefs.h: grammar.c
grammar.c: $(srcdir)/grammar.y
	@rm -f grammar.c tokdefs.h
	$(YACC) -d $<
	mv y.tab.c grammar.c
	mv y.tab.h tokdefs.h

grammar.o: grammar.c
	@rm -f $@
	$(CC) $(FULL_CFLAGS) -Dyylval=pcap_lval -c grammar.c

version.o: version.c
	$(CC) $(FULL_CFLAGS) -c version.c

snprintf.o: $(srcdir)/missing/snprintf.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/snprintf.c

version.c: $(srcdir)/VERSION
	@rm -f $@
	if grep GIT ${srcdir}/VERSION >/dev/null; then \
		read ver <${srcdir}/VERSION; \
		echo $$ver | tr -d '\012'; \
		date +_%Y_%m_%d; \
	else \
		cat ${srcdir}/VERSION; \
	fi | sed -e 's/.*/char pcap_version[] = "&";/' > $@

#
# NOTE: this really is supposed to be static; importing a string
# from a shared library does not work very well on many
# versions of UNIX (Solaris, Linux, and the BSDs, for example),
# so we make the version string static and return it from
# a function, which does work.
#
version.h: $(srcdir)/VERSION
	@rm -f $@
	if grep GIT ${srcdir}/VERSION >/dev/null; then \
		read ver <${srcdir}/VERSION; \
		echo $$ver | tr -d '\012'; \
		date +_%Y_%m_%d; \
	else \
		cat ${srcdir}/VERSION; \
	fi | sed -e 's/.*/static const char pcap_version_string[] = "libpcap version &";/' > $@

bpf_filter.c: $(srcdir)/bpf/net/bpf_filter.c
	rm -f bpf_filter.c
	ln -s $(srcdir)/bpf/net/bpf_filter.c bpf_filter.c

bpf_filter.o: bpf_filter.c
	$(CC) $(FULL_CFLAGS) -c bpf_filter.c

clean:
	rm -f  $(CLEANFILES)

romfs:
	echo "Do nothing"

#$(ROMFSINST) libpcap.a /usr	
#$(ROMFSINST) libpcap.so.1.4.0 /usr




