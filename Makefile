# $Id$

WARN     = -Wall -Werror -Wstrict-prototypes
LIBS     = -lmilter -lpthread
PROGNAME = dnsbl-milter

INCDIRS  = /usr/include/libmilter/
LIBDIRS  = /usr/lib/

default all: main

main: dnsbl-milter.c
	$(CC) $(WARN) $(CFLAGS) -D_REENTRANT dnsbl-milter.c -o $(PROGNAME) $(LIBS) -I $(INCDIRS) -L $(LIBDIRS)

clean:
	[[ -e "$(PROGNAME)" ]] && rm -f $(PROGNAME)

