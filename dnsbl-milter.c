/**
 * $Id$
 *
 * dnsbl-milter.c - lightweight sendmail DNSBL & DNSWL milter
 * <http://dnsbl-milter.sourceforge.net/>
 *
 * Copyright 2007, 2008, 2009 Haw Loeung <hloeung@users.sourceforge.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <netdb.h>
#include <pwd.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
# ifndef S_SPLINT_S
#include <syslog.h>
# endif
#include <time.h>
#include <unistd.h>

#include "libmilter/mfapi.h"
#define GETCONTEXT(ctx)  ((struct mlfiPriv *) smfi_getpriv(ctx))


#define DNSL_NEXIST 0
#define DNSL_EXIST  1
#define DNSL_FAIL   2
typedef uint8_t dnsl_t;

static dnsl_t dns_check(const uint8_t, const uint8_t, const uint8_t,
			const uint8_t, const char *);


struct listNode {
	char *dnsl;
	char *msg;
	struct listNode *next;
};

struct listNode *blacklist;
struct listNode *whitelist;

static int list_add(struct listNode **, const char *, const char *);
static int list_free(struct listNode **);


#define STAMP_PASSED      0
#define STAMP_WHITELISTED 1
#define STAMP_SKIPPED     2
typedef uint8_t stamp_t;

struct mlfiPriv {
	char *connectfrom;
	uint32_t hostaddr;	/* network byte order */
	char *msgid;
	char *envfrom;
	uint8_t check;
	stamp_t stamp;
};

sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat mlfi_envfrom(SMFICTX *, char **);
sfsistat mlfi_eom(SMFICTX *);
sfsistat mlfi_abort(SMFICTX *);
sfsistat mlfi_close(SMFICTX *);
#if SMFI_VERSION > 3
sfsistat mlfi_data(SMFICTX *);
#endif
static sfsistat mlfi_cleanup(SMFICTX *);
static sfsistat mlfi_dnslcheck(SMFICTX *);

struct smfiDesc smfilter = {
	"dnsbl-milter",		/* filter name */
	SMFI_VERSION,		/* version code -- do not change */
	(unsigned long int) SMFIF_ADDHDRS,	/* flags */
	mlfi_connect,		/* connection info filter */
	NULL,			/* SMTP HELO command filter */
	mlfi_envfrom,		/* envelope sender filter */
	NULL,			/* envelope recipient filter */
	NULL,			/* header filter */
	NULL,			/* end of header */
	NULL,			/* body block filter */
	mlfi_eom,		/* end of message */
	mlfi_abort,		/* message aborted */
	mlfi_close,		/* connection cleanup */
#if SMFI_VERSION > 2
	NULL,			/* unknown SMTP commands */
#endif				/* SMFI_VERSION > 2 */
#if SMFI_VERSION > 3
	mlfi_data,		/* DATA command */
	NULL,			/* Once, at the start of each SMTP
				   connection */
#endif				/* SMFI_VERSION > 3 */
};

static void usage(const char *);
static void mlog(const int, const char *, ...);
static void daemonize(void);
static int drop_privs(const char *, const char *);
static void pidf_create(const char *);
static void pidf_destroy(const char *);

#ifdef __linux__
# define HAS_LONGOPT 1
# include <getopt.h>
#else
# define getopt_long(argc,argv,opts,lopt,lind) getopt(argc,argv,opts)
#endif

struct config {
	char *pname;
	uint8_t daemon;
	uint8_t stamp;
} config;

int main(int argc, char **argv)
{
	const char *opts = "b:D:dg:hst:u:";
#ifdef HAS_LONGOPT
	static const struct option lopt[] = {
		{"bind", 1, 0, 'b'},
		{"debug", 1, 0, 'D'},
		{"daemonize", 0, 0, 'd'},
		{"group", 1, 0, 'g'},
		{"help", 0, 0, 'h'},
		{"no-stamp", 0, 0, 's'},
		{"timeout", 1, 0, 't'},
		{"user", 1, 0, 'u'},
		{NULL, 0, 0, 0}
	};
#endif
	int c;
	char *p;
	char *oconn;
	int setconn;
	size_t len;
	int ret;
	uint8_t daemon;
	char *usr;
	char *grp;
	char *pidf = "/var/run/milter/dnsbl-milter.pid";

	config.pname = argv[0];
	p = strrchr(config.pname, '/');
	if (p != NULL)
		config.pname = p + 1;

	if (argc < 2) {
		usage(config.pname);
		exit(EX_USAGE);
	}

	setconn = 0;
	oconn = NULL;
	config.daemon = 0;
	daemon = 0;
	usr = grp = NULL;
	config.stamp = 1;

	while ((c = getopt_long(argc, argv, opts, lopt, NULL)) != -1) {

		switch (c) {

		case 'b':	/* bind address/socket */
			if (setconn != 0) {
				mlog(LOG_ERR,
				     "Bind address/socket already provided, ignoring");
				break;
			}

			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR,
				     "No bind address/socket provided");
				usage(config.pname);
				exit(EX_USAGE);
			}

			if ((strncmp(optarg, "unix:", 5) == 0) ||
			    (strncmp(optarg, "local:", 6) == 0) ||
			    (strncmp(optarg, "inet:", 5) == 0) ||
			    (strncmp(optarg, "inet6:", 6) == 0)) {
				oconn = optarg;
				setconn = 1;
				break;
			}

			/* "unix:" + optarg + '\0' */
			len = 5 + strlen(optarg) + 1;
			oconn = malloc(len);
			if (oconn == NULL) {
				mlog(LOG_ERR, "Memory allocation failed");
				exit(EX_UNAVAILABLE);
			}

			snprintf(oconn, len, "unix:%s", optarg);
			setconn = 2;
			break;

		case 'D':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR,
				     "No debugging level provided");
				usage(config.pname);
				exit(EX_USAGE);
			}

			smfi_setdbg(atoi(optarg));
			break;

		case 'd':
			daemon = 1;
			break;

		case 'g':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR, "No group provided");
				usage(config.pname);
				exit(EX_USAGE);
			}

			grp = optarg;
			break;

		case 's':
			config.stamp = 0;
			break;

		case 't':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR, "No timeout provided");
				usage(config.pname);
				exit(EX_USAGE);
			}

			smfi_settimeout(atoi(optarg));
			break;

		case 'u':
			if ((optarg == NULL) || (*optarg == '\0')) {
				mlog(LOG_ERR, "No user provided");
				usage(config.pname);
				exit(EX_USAGE);
			}

			usr = optarg;
			break;

		case 'h':	/* help */
		default:
			usage(config.pname);
			exit(EX_USAGE);
		}
	}

	if (setconn == 0) {
		mlog(LOG_ERR, "%s: Missing required bind address/socket\n",
		     config.pname);
		usage(config.pname);
		exit(EX_USAGE);
	}

	umask(0137);

	if ((oconn == NULL) || (smfi_setconn(oconn) == MI_FAILURE)) {
		mlog(LOG_ERR, "smfi_setconn() failed");
		exit(EX_UNAVAILABLE);
	}

	if (smfi_register(smfilter) == MI_FAILURE) {
		mlog(LOG_ERR, "smfi_register() failed");
		exit(EX_UNAVAILABLE);
	}

	/* List of blacklists to use */
	list_add(&blacklist, "bl.spamcop.net",
		 "Listed on SpamCop. See http://spamcop.net/w3m?action=checkblock&ip=");
	list_add(&blacklist, "b.barracudacentral.org",
		 "Listed on Barracuda Reputation Block List (BRBL). See http://www.barracudacentral.org/lookups?ip_address=");
	list_add(&blacklist, "zen.spamhaus.org",
		 "Listed on The Spamhaus Project. See http://www.spamhaus.org/query/bl?ip=");
	list_add(&blacklist, "psbl.surriel.com",
		 "Listed on The Passive Spam Block List. See http://psbl.surriel.com/listing?ip=");

	/* List of whitelists to use */
	list_add(&whitelist, "list.dnswl.org", "http://www.dnswl.org");

	if ((usr != NULL) || (grp != NULL))
		if (drop_privs(usr, grp) != 0)
			exit(EX_TEMPFAIL);

	if (daemon != 0)
		daemonize();

	/* write pid file */
	pidf_create(pidf);

	mlog(LOG_INFO, "Starting Sendmail %s filter '%s'",
	     smfilter.xxfi_name, config.pname);
	ret = smfi_main();
	/* remove pid file */
	pidf_destroy(pidf);
	if (ret == MI_SUCCESS) {
		mlog(LOG_INFO, "Stopping Sendmail %s filter '%s'",
		     smfilter.xxfi_name, config.pname);
	} else {
		mlog(LOG_ERR,
		     "Abnormal termination of Sendmail %s filter '%s': %d",
		     smfilter.xxfi_name, config.pname, ret);
	}

	list_free(&blacklist);
	list_free(&whitelist);

	if (setconn == 2) {
		free(oconn);
		oconn = NULL;
	}

	if (daemon != 0)
		closelog();

	return ret;
}

static void usage(const char *prog)
{
	printf("\
Usage: %s -b [bind address/socket] [-dh] [-D [debug level]]\n\
       [-t [milter timeout in seconds] [-u [user]] [-g [group]] \n", prog);

	printf("\n\
    -b addr/socket  Bind address or UNIX socket. E.g. inet:1234@127.0.0.1\n\
\n\
    -d              Daemonize and run in the background. Default runs milter\n\
                    in foreground\n\
    -D level        Set milter library's internal debugging level. (max: 6)\n\
    -t seconds      Sets the number of seconds libmilter will wait for an MTA\n\
                    connection before timing out a socket. (default: 7210)\n\
    -u user         Run as user \"user\"\n\
    -g group        Run as group \"group\"\n\
\n\
    -h              This help screen\n");

	printf
	    ("\nReport bugs to Haw Loeung <hloeung@users.sourceforge.net>\n\
$Id$\n");

}

static void mlog(const int priority, const char *fmt, ...)
{
	char tbuf[15];
	time_t t;
	struct tm tm;
	va_list ap;

	va_start(ap, fmt);

	/* if daemonize, then we log to syslog */
	if (config.daemon != 0)
		vsyslog(priority, fmt, ap);

	else {
		t = time(NULL);
		strftime(tbuf, sizeof(tbuf), "%b %e %T",
			 localtime_r(&t, &tm));
		fprintf(stderr, "%.15s ", tbuf);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}

	va_end(ap);
}

sfsistat mlfi_connect(SMFICTX * ctx, char *hostname, _SOCK_ADDR * hostaddr)
{
	struct mlfiPriv *priv;
	struct sockaddr_in *phostaddr;

	/* unsupported type */
	if (hostaddr == NULL) {
		mlog(LOG_ERR, "%s: %s: Unsupported type", hostname,
		     "mlfi_connect()");
		return SMFIS_ACCEPT;
	}

	/* allocate some private memory */
	priv = malloc(sizeof *priv);
	if (priv == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed", hostname,
		     "mlfi_connect()");
		return SMFIS_TEMPFAIL;
	}
	bzero(priv, sizeof *priv);

	/* save the private data */
	smfi_setpriv(ctx, priv);

	/* store hostname of the SMTP client */
	priv->connectfrom = strdup(hostname);
	if (priv->connectfrom == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed", hostname,
		     "mlfi_connect()");
		return SMFIS_TEMPFAIL;
	}

	/* store hostaddr */
	phostaddr = (struct sockaddr_in *) hostaddr;
	priv->hostaddr = htonl(phostaddr->sin_addr.s_addr);

	/* continue processing */
	return SMFIS_CONTINUE;
}

sfsistat mlfi_envfrom(SMFICTX * ctx, char **argv)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);
	char *msgid;

	/* SMTP Authenticated. Skip DNS blacklist checks */
	if (smfi_getsymval(ctx, "{auth_type}") != NULL)
		return SMFIS_ACCEPT;

	/* store message ID */
	msgid = smfi_getsymval(ctx, "{i}");
	if (msgid != NULL) {
		priv->msgid = strdup(msgid);
		if (priv->msgid == NULL) {
			mlog(LOG_ERR, "%s: %s: Memory allocation failed",
			     priv->connectfrom, "mlfi_envfrom()");
			mlfi_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}
	}

	else {
		/* TODO: Replace with code to generate Sendmail msgid */
		priv->msgid = strdup(priv->connectfrom);
	}

	/* store sender's address */
	priv->envfrom = strdup(argv[0]);
	if (priv->envfrom == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     priv->msgid, "mlfi_envfrom()");
		mlfi_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

#if SMFI_VERSION > 3
	/* null-envelope sender address, defer DNS checks till mlfi_data() */
	if (strncmp(argv[0], "<>\0", 3) == 0) {
#ifdef DEBUG
		mlog(LOG_DEBUG,
		     "%s: Null-envelope sender address, deferring",
		     priv->msgid);
#endif
		priv->check = 1;
		return SMFIS_CONTINUE;
	}
#endif

	priv->check = 0;
	return mlfi_dnslcheck(ctx);
}

sfsistat mlfi_eom(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);

	if (config.stamp == 0)
		return mlfi_cleanup(ctx);

	switch (priv->stamp) {
	case STAMP_PASSED:
		smfi_insheader(ctx, 0, "X-DNSBL-MILTER", "Passed");
		break;
	case STAMP_WHITELISTED:
		smfi_insheader(ctx, 0, "X-DNSBL-MILTER", "Whitelisted");
		break;
	case STAMP_SKIPPED:
		smfi_insheader(ctx, 0, "X-DNSBL-MILTER", "Skipped");
		break;
	default:
		smfi_insheader(ctx, 0, "X-DNSBL-MILTER", "Unknown error");
		break;
	}

	return mlfi_cleanup(ctx);
}

sfsistat mlfi_abort(SMFICTX * ctx)
{
	return mlfi_cleanup(ctx);
}

sfsistat mlfi_close(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);

	if (priv == NULL)
		return SMFIS_CONTINUE;

	/* mlfi_connectfrom() */
	if (priv->connectfrom != NULL) {
		free(priv->connectfrom);
		priv->connectfrom = NULL;
	}

	free(priv);
	priv = NULL;
	smfi_setpriv(ctx, NULL);

	/* continue processing */
	return SMFIS_CONTINUE;
}

#if SMFI_VERSION > 3
sfsistat mlfi_data(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);

	if (priv->check != 0)
		return mlfi_dnslcheck(ctx);

	/* continue processing */
	return SMFIS_CONTINUE;
}
#endif

static sfsistat mlfi_cleanup(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);

	if (priv == NULL)
		return SMFIS_CONTINUE;

	/* mlfi_envfrom() */
	if (priv->msgid != NULL) {
		free(priv->msgid);
		priv->msgid = NULL;
	}

	if (priv->envfrom != NULL) {
		free(priv->envfrom);
		priv->envfrom = NULL;
	}

	/* continue processing */
	return SMFIS_CONTINUE;
}

static sfsistat mlfi_dnslcheck(SMFICTX * ctx)
{
	struct mlfiPriv *priv = GETCONTEXT(ctx);
	struct listNode *blp;
	uint8_t blisted;
	struct listNode *wlp;
	uint8_t wlisted;
	size_t len;
	char *msg;

	uint8_t a = (priv->hostaddr & 0xff000000) >> 24;
	uint8_t b = (priv->hostaddr & 0x00ff0000) >> 16;
	uint8_t c = (priv->hostaddr & 0x0000ff00) >> 8;
	uint8_t d = (priv->hostaddr & 0x000000ff);

	switch (a) {

		/* Loopback */
	case 127:
		priv->stamp = STAMP_SKIPPED;
		return SMFIS_CONTINUE;
		break;

		/* RFC1910 (Private networks) */
	case 10:		/* Class A (10.0.0.0/8) */
		priv->stamp = STAMP_SKIPPED;
		return SMFIS_CONTINUE;
		break;
	case 172:
		/* Class B (172.16.0.0/12) */
		if ((b & 0xf0) == 0x10) {
			priv->stamp = STAMP_SKIPPED;
			return SMFIS_CONTINUE;
		}
		break;
	case 192:
		/* Class C (192.168.0.0/16) */
		if (b == 168) {
			priv->stamp = STAMP_SKIPPED;
			return SMFIS_CONTINUE;
		}
		break;

	default:
		break;
	}

	/* blacklist */
	blp = blacklist;
	blisted = 0;
	while ((blp != NULL) && (blisted == 0)) {
#ifdef DEBUG
		mlog(LOG_DEBUG, "%s: Looking up %u.%u.%u.%u.%s.",
		     priv->msgid, d, c, b, a, blp->dnsl);
#endif

		if (dns_check(a, b, c, d, blp->dnsl) == DNSL_EXIST) {
			mlog(LOG_INFO,
			     "%s: %s [%u.%u.%u.%u] is blacklisted on %s",
			     priv->msgid, priv->connectfrom, a, b, c, d,
			     blp->dnsl);
			blisted = 1;
		} else
			blp = blp->next;
	}

	if (blisted == 0) {
		priv->stamp = STAMP_PASSED;
		return SMFIS_CONTINUE;
	}

	/* whitelist */
	wlp = whitelist;
	wlisted = 0;
	while ((wlp != NULL) && (wlisted == 0)) {
#ifdef DEBUG
		mlog(LOG_DEBUG, "%s: Looking up %u.%u.%u.%u.%s.",
		     priv->msgid, d, c, b, a, wlp->dnsl);
#endif

		if (dns_check(a, b, c, d, wlp->dnsl) == DNSL_EXIST) {
			mlog(LOG_INFO,
			     "%s: %s [%u.%u.%u.%u] is whitelisted on %s",
			     priv->msgid, priv->connectfrom, a, b, c, d,
			     wlp->dnsl);
			wlisted = 1;
		} else
			wlp = wlp->next;
	}

	if (wlisted != 0) {
		priv->stamp = STAMP_WHITELISTED;
		return SMFIS_CONTINUE;
	}

	/* "Client address [aaa.bbb.ccc.ddd] blocked. " + msg + "aaa.bbb.ccc.ddd"
	   + '\0' */
	len = 43 + strlen(blp->msg) + 15 + 1;
	msg = malloc(len);
	if (msg == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     priv->msgid, "mlfi_dnslcheck()");
		smfi_setreply(ctx, "550", "5.7.1", blp->msg);
	} else {
		snprintf(msg, len,
			 "Client address [%u.%u.%u.%u] blocked. %s%u.%u.%u.%u",
			 (unsigned int) a, (unsigned int) b,
			 (unsigned int) c, (unsigned int) d, blp->msg,
			 (unsigned int) a, (unsigned int) b,
			 (unsigned int) c, (unsigned int) d);
		smfi_setreply(ctx, "550", "5.7.1", msg);
		free(msg);
		msg = NULL;
	}

	mlfi_cleanup(ctx);
	return SMFIS_REJECT;
}

static dnsl_t dns_check(const uint8_t a, const uint8_t b, const uint8_t c,
			const uint8_t d, const char *dnsl)
{
	size_t len;
	char *name;
	int err;
	struct addrinfo *res = NULL;

	/* "ddd.ccc.bbb.aaa" + '.' + dnsl + '.' + '\0' */
	len = 15 + 1 + strlen(dnsl) + 1 + 1;
	name = malloc(len);
	if (name == NULL) {
		mlog(LOG_ERR, "%s: Memory allocation failed",
		     "dns_check()");
		return DNSL_FAIL;
	}

	snprintf(name, len, "%u.%u.%u.%u.%s.", (unsigned int) d,
		 (unsigned int) c, (unsigned int) b, (unsigned int) a,
		 dnsl);
	err = getaddrinfo(name, NULL, NULL, &res);
	free(name);
	name = NULL;

	if (res != NULL)
		freeaddrinfo(res);

	switch (err) {
	case 0:		/* successful lookup */
		return DNSL_EXIST;
		break;
	case EAI_AGAIN:
	case EAI_MEMORY:
		return DNSL_FAIL;
		break;
	default:
		return DNSL_NEXIST;
		break;
	}
}


static int list_add(struct listNode **listp, const char *dnsl,
		    const char *msg)
{
	struct listNode *node;
	struct listNode *p;

	node = malloc(sizeof(struct listNode));
	if (node == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     "list_add()", "malloc(node)");
		return 1;
	}

	node->dnsl = strdup(dnsl);
	if (node->dnsl == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     "list_add()", "strdup(dnsl)");
		free(node);
		node = NULL;
		return 1;
	}

	if (msg == NULL)
		node->msg = strdup("Listed on DNS List");
	else
		node->msg = strdup(msg);
	if (node->msg == NULL) {
		mlog(LOG_ERR, "%s: %s: Memory allocation failed",
		     "list_add()", "strdup(msg)");
		free(node->dnsl);
		free(node);
		node = NULL;
		return 1;
	}
	node->next = NULL;

	if (*listp == NULL) {
		*listp = node;
		goto success;
	}

	p = (struct listNode *) *listp;
	while (p->next != NULL)
		p = p->next;

	p->next = node;

      success:
	mlog(LOG_DEBUG, "Added to list %s %s", dnsl, msg);
	return 0;
}

static int list_free(struct listNode **listp)
{
	struct listNode *node;
	struct listNode *p;

	p = (struct listNode *) *listp;
	*listp = NULL;

	while (p != NULL) {
		node = p;
		p = p->next;

		free(node->dnsl);
		node->dnsl = NULL;
		free(node->msg);
		node->msg = NULL;
		free(node);
	}

	return 0;
}

static void daemonize(void)
{
	int i;

	config.daemon = 1;

	openlog(config.pname, LOG_PID, LOG_LOCAL6);

	i = fork();
	if (i == -1)
		exit(EX_UNAVAILABLE);
	if (i > 0)
		exit(0);

	setsid();
	if (chdir("/") != 0)
		exit(EX_UNAVAILABLE);

	for (i = getdtablesize(); i >= 0; i--)
		close(i);

	/* handle stdin, stdout, and stderr */
	i = open("/dev/null", O_RDWR);
	if (dup(i) == -1)
		exit(EX_UNAVAILABLE);
	if (dup(i) == -1)
		exit(EX_UNAVAILABLE);
}

static int drop_privs(const char *usr, const char *grp)
{
	struct passwd *pw = NULL;
	struct group *gr = NULL;

	/*
	 * there is only one thread yet, so it is safe to use non reentrant
	 * functions such as getpwent and getgrnam
	 */

	if ((usr == NULL) && (grp == NULL))
		return 0;

	/* return if we're not root */
	if (getuid() != 0) {
		mlog(LOG_ERR, "Unable to set UID or GID");
		return -1;
	}

	/* GID */
	if (grp != NULL) {
		gr = getgrnam(grp);
		if (gr == NULL) {
			mlog(LOG_ERR, "Group \"%s\" not found", grp);
			return -1;
		}

		if (setgid(gr->gr_gid) != 0) {
			mlog(LOG_ERR, "Unable to setgid to %d",
			     gr->gr_gid);
			return -1;
		}
	}

	/* UID */
	if (usr != NULL) {
		pw = getpwnam(usr);
		if (pw == NULL) {
			mlog(LOG_ERR, "User \"%s\" not found", usr);
			return -1;
		}

		if (setuid(pw->pw_uid) != 0) {
			mlog(LOG_ERR, "Unable to setuid to %d",
			     pw->pw_uid);
			return -1;
		}
	}

	return 0;
}

static void pidf_create(const char *pidf)
{
	FILE *fp;

	fp = fopen(pidf, "w");
	if (fp == NULL) {
		mlog(LOG_ERR, "Unable to create PID file");
		return;
	}

	fprintf(fp, "%d\n", getpid());
	fclose(fp);
}

static void pidf_destroy(const char *pidf)
{
	unlink(pidf);
}
