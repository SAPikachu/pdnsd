# Following are the variables you should set to values describing your local
# system
#------------------------------------------------------------------------------
# PDNSD_CACHEDIR is an environment variable that is used to pass configuration
# options to pdsnd in RPM configuration. If you do not use RPM but compile
# manually, uncomment the following line to change the cache directory to
# anything other than /var/cache/pdnsd
# The following line is e.g. suitable for Red Hat, if you do not want
# a /var/cache directory only for pdnsd:
#PDNSD_CACHEDIR=/var/spool/pdnsd
# the standard directory (FSSTND compliant):
PDNSD_CACHEDIR=/var/cache/pdnsd
# your C compiler command. If gcc doesn't work, try cc. However note that you 
# NEED gcc (but it's named cc on some systems). See README
CC=gcc
# your lex/flex command (not always needed; see INSTALL)
LEX=flex
# your yacc/bison command (not always needed; see INSTALL)
YACC=bison
# strict C compiler flags. Note that some warnings are normal.
STRICT_CF=-Wstrict-prototypes -Wall -pedantic # -Wmissing-prototypes  -Wpointer-arith
# The flags given in the C compiler call (these are for gcc)
CFLAGS=-g -W -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmultichar -Wparentheses -Wswitch -Wunused $(STRICT_CF)
# The flags given for bison/yacc; OK for bison, remove the -y for yacc
YACCFLAGS=-y -d
# the flags given for lex; should be OK for lex and flex
LEXFLAGS=-i
# The needed libraries.
# Using flex, I don't need to do -lfl if I provide both yywrap() and main(), and
# so I rather don't do it because it may not be thread-safe (the lexer is not 
# used multithreaded, but that may change). Does anyone know if under that
# conditions I do not need -ll when using lex?
#
# The following line is for linux: 
LIBS=-lpthread -lefence
# and this for BSD:
#LIBS=-lc_r
#------------------------------------------------------------------------------
# (End of options) 
# The following lines just define variables for the C compiler derived from the
# options above. You should not need to change them if you C compiler and make
# are OK.
DEFINES=-DCACHEDIR=\"$(PDNSD_CACHEDIR)\"

OBJS=conff.o y.tab.o lex.yy.o hash.o error.o helpers.o cache.o icmp.o status.o netdev.o servers.o dns_answer.o dns_query.o dns.o main.o
CSOURCES=conff.c y.tab.c lex.yy.c hash.c error.c helpers.c cache.c icmp.c status.c netdev.c servers.c dns_answer.c dns_query.c dns.c main.c
CHEADERS=cache.h consts.h dns_query.h helpers.h lex.inc.h status.h conff.h dns.h error.h icmp.h netdev.h y.tab.h config.h dns_answer.h hash.h ipvers.h servers.h

.PHONY:all dep deps ChangeLog

all:pdnsd

deps: .deps

dep: .deps

.deps: $(CSOURCES) $(CHEADERS)
	-rm -f .deps
	for i in $(CSOURCES) ; do $(CC) -MM -MG $(DEFINES) $$i >> .deps ; echo -e "\\t" '$$(CC) $$(CFLAGS) $$(DEFINES) -c' "$$i\\n\\n" >> .deps; done

# The .c to .o rules are in .deps, which is made by make deps. Have a look at
# the deps rule if you want to change something.
# .deps in turn is dependent on $(CSOURCES) and $(CHEADERS).
$(OBJS): .deps 
	make -f .deps CC='$(CC)' CFLAGS='$(CFLAGS)' DEFINES='$(DEFINES)' $(OBJS)

pdnsd: .deps $(OBJS)  
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o pdnsd

y.tab.c y.tab.h: conf.y
	$(YACC) conf.y  $(YACCFLAGS)

lex.yy.c lex.inc.h: conf.l.templ
	./exec-flex.sh $(LEX) $(CC) conf.l conf.l.templ $(LEXFLAGS) 

config.h: version config.h.templ
	v=`cat version` ; sed -e "s/\\/\\*VERSION-INSERT-LOC\\*\\//#define VERSION \"$$v\"/" config.h.templ > config.h

ChangeLog:
	rcs2log -R -u "thomas	Thomas Moestl	tmoestl@gmx.net" > ChangeLog

.PHONY: all clean mclean distclean dist install

clean:
	-rm -f y.output
	-rm -f $(OBJS)
	-rm -f pdnsd
	-rm -f config.h
	-rm -f pdnsd-suse.spec
	-rm -f pdnsd-redhat.spec

mclean: clean
	-rm -f conf.l
	-rm -f y.tab.c
	-rm -f y.tab.h
	-rm -f lex.yy.c
	-rm -f .deps

distclean: clean
	-rm -f *~
	-rm -f doc/*~
	-rm -f doc/html/*~
	-rm -f doc/txt/*~
	-rm -f rc/*~
	-rm -f rc/SuSE/*~
	-rm -f rc/Redhat/*~

dist: lex.yy.c y.tab.c y.tab.h distclean doc ChangeLog
	v=`cat version` ; udir=`pwd | awk -F / '{print $$NF}'` ; cd ..  ; dir=pdnsd-$$v ; ard="n" ; if [ $$udir != $$dir ] ; then ard="y" ; ln -s $$udir $$dir ; fi ; tar -cf pdnsd-$$v.tar $$dir/* --exclude="*doc/rfc*" ; cat pdnsd-$$v.tar | gzip >pdnsd-$$v.tar.gz ; bzip2 -f pdnsd-$$v.tar ; if [ $$ard == "y" ] ; then rm $$dir ; fi

suserpm: dist pdnsd-suse.spec
	su -c "cp -f ../pdnsd-`cat version`.tar.gz /usr/src/packages/SOURCES;rpm -ba pdnsd-suse.spec; chown thomas.users *"
	cp -f /usr/src/packages/SRPMS/pdnsd-`cat version`-1.src.rpm ../pdnsd-`cat version`.suse.src.rpm
	cp -f /usr/src/packages/RPMS/i386/pdnsd-`cat version`-1.i386.rpm ../pdnsd-`cat version`.i386.suse.rpm

pdnsd-suse.spec: version pdnsd-suse.spec.templ
	v=`cat version` ; sed pdnsd-suse.spec.templ -e "s/\\/\\*VERSION-INSERT-LOC\\*\\//$$v/" > pdnsd-suse.spec

rhrpm: 	dist pdnsd-redhat.spec
	su -c "cp -f ../pdnsd-`cat version`.tar.gz /usr/src/redhat/SOURCES;rpm -ba pdnsd-redhat.spec; chown thomas.users *"
	cp -f /usr/src/redhat/SRPMS/pdnsd-`cat version`-1.src.rpm ../pdnsd-`cat version`.redhat.src.rpm
	cp -f /usr/src/redhat/RPMS/i386/pdnsd-`cat version`-1.i386.rpm ../pdnsd-`cat version`.i386.redhat.rpm

pdnsd-redhat.spec: version pdnsd-redhat.spec.templ
	v=`cat version` ; sed pdnsd-redhat.spec.templ -e "s/\\/\\*VERSION-INSERT-LOC\\*\\//$$v/" > pdnsd-redhat.spec

install:
	if [ -e /etc/pdnsd.conf ] ; then cp /etc/pdnsd.conf /etc/pdnsd.conf.old ; echo -e "\n\033[31mBacked up your old /etc/pdnsd.conf to /etc/pdnsd.conf.old\033[m\n"; fi
#	cp doc/pdnsd.conf /etc/pdnsd.conf
#	chmod go-w /etc/pdnsd.conf
#	cp pdnsd /usr/sbin/
#	chown root.root /usr/sbin/pdnsd
#	chmod 755 /usr/sbin/pdnsd
#	if [ ! -d /var ] ; then mkdir /var ; chown root.root /var ; chmod 755 /var ; fi
#	if [ ! -d /var/cache ] ; then mkdir /var/cache ; chown root.root /var/cache ; chmod 755 /var/cache ; fi
#	if [ ! -d /var/cache/pdnsd ] ; then mkdir /var/cache/pdnsd ; chown root.root /var/cache/pdnsd ; chmod 700 /var/cache/pdnsd ; fi
	# Thanks to Soenke J. Peters for suggestions on the Makefile rules!
	install -o root -g root -m 600 doc/pdnsd.conf /etc/pdnsd.conf
	install -o root -g root -m 755 pdnsd /usr/sbin
	install -d -o root -g root $(PDNSD_CACHEDIR)
	# Make sure the cache file permissions are correct.
	if [ -f $(PDNSD_CACHEDIR)/pdnsd.cache ] ; then chmod 0600 $(PDNSD_CACHEDIR)/pdnsd.cache ; fi
	echo -e "\033[31m\nYou should edit your /etc/pdnsd.conf to adapt it to your system configuration.\033[m\n"

# This is to generate the docs from my master copy. If you want to modify the docs or package your own or whatever, either modify
# this rule (an empty one will do if you did not change the documentation), or get the html docs package from my download page
# and untar it in the pdnsd parent directory.
doc: doc/html/index.html doc/html/doc.html doc/html/faq.html doc/html/dl.html doc/txt/intro.txt doc/txt/manual.txt doc/txt/faq.txt

doc/html/index.html: ../html/index.html
	sed -e 's/<!--nodoc(-->/<!--/g' -e 's/<!--)nodoc-->/-->/g' ../html/index.html  > doc/html/index.html

doc/html/doc.html: ../html/doc.html
	sed -e 's/<!--nodoc(-->/<!--/g' -e 's/<!--)nodoc-->/-->/g' ../html/doc.html  > doc/html/doc.html

doc/html/faq.html:  ../html/faq.html
	sed -e 's/<!--nodoc(-->/<!--/g' -e 's/<!--)nodoc-->/-->/g' ../html/faq.html  > doc/html/faq.html

doc/html/dl.html:  ../html/subst/dl.html
	sed -e 's/<!--nodoc(-->/<!--/g' -e 's/<!--)nodoc-->/-->/g' ../html/subst/dl.html  > doc/html/dl.html


doc/txt/intro.txt: doc/html/index.html
	sed -e 's/<!--notext(-->/<!--/g' -e 's/<!--)notext-->/-->/g' doc/html/index.html | html2text > doc/txt/intro.txt

doc/txt/manual.txt: doc/html/doc.html
	sed -e 's/<!--notext(-->/<!--/g' -e 's/<!--)notext-->/-->/g' doc/html/doc.html | html2text > doc/txt/manual.txt

doc/txt/faq.txt: doc/html/faq.html
	sed -e 's/<!--notext(-->/<!--/g' -e 's/<!--)notext-->/-->/g' doc/html/faq.html | html2text > doc/txt/faq.txt