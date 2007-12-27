# $Id$

WARN     = -Wall -Werror -Wstrict-prototypes
LIBS     = -lmilter -lpthread
PROGNAME = dnsbl-milter

INSTPATH = /usr/local/sbin/

INCDIRS  = /usr/include/libmilter/
LIBDIRS  = /usr/lib/

default all: main

main: dnsbl-milter.c
	$(CC) $(WARN) $(CFLAGS) -D_REENTRANT dnsbl-milter.c -o $(PROGNAME) $(LIBS) -I $(INCDIRS) -L $(LIBDIRS)

install: dnsbl-milter
	[[ -e "$(INSTPATH)/$(PROGNAME)" ]] && cp -af "$(INSTPATH)/$(PROGNAME)" "$(INSTPATH)/$(PROGNAME).bak" || true
	install -m 755 -D $(PROGNAME) $(INSTPATH)/$(PROGNAME)

clean:
	[[ -e "$(PROGNAME)" ]] && rm -f $(PROGNAME)

