/***********************************************************************
*
* pppoe-server.c
*
* Implementation of a user-space PPPoE server
*
* Copyright (C) 2000-2012 Roaring Penguin Software Inc.
* Copyright (C) 2018-2023 Dianne Skoll
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* $Id$
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
***********************************************************************/

#include "config.h"

#include <sys/socket.h>

#if defined(HAVE_NETPACKET_PACKET_H) || defined(HAVE_LINUX_IF_PACKET_H)
#define _POSIX_SOURCE 1 /* For sigaction defines */
#endif

#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <time.h>
#include <signal.h>
#include <stdarg.h>

#include "pppoe-server.h"
#include "md5.h"
#include "control_socket.h"


#if defined(HAVE_LINUX_IF_H)
#include <linux/if.h>
#endif

static void InterfaceHandler(EventSelector *es,
			int fd, unsigned int flags, void *data);
static void startPPPD(ClientSession *sess);
static void sendErrorPADS(int sock, unsigned char *source, unsigned char *dest,
			  int errorTag, char *errorMsg);

#define CHECK_ROOM(cursor, start, len) \
do {\
    if (((cursor)-(start))+(len) > MAX_PPPOE_PAYLOAD) { \
	syslog(LOG_ERR, "Would create too-long packet"); \
	return; \
    } \
} while(0)

#define DRAIN_OFF	0
#define DRAIN_ON	1
#define DRAIN_QUIT	2
static const char* drain_string[] = {
    "off (actively accepting connection)",
    "on (not accepting connections)",
    "quit (not accepting, will terminate when drained)",
};

static char *plugin_path = PLUGIN_PATH;

static void PppoeStopSession(ClientSession *ses, char const *reason);
static int PppoeSessionIsActive(ClientSession *ses);

/* Service-Names we advertise */
#define MAX_SERVICE_NAMES 64
static int NumServiceNames = 0;
static char const *ServiceNames[MAX_SERVICE_NAMES];

PppoeSessionFunctionTable DefaultSessionFunctionTable = {
    PppoeStopSession,
    PppoeSessionIsActive,
    NULL
};

/* An array of client sessions */
ClientSession *Sessions = NULL;
ClientSession *FreeSessions = NULL;
ClientSession *LastFreeSession = NULL;
ClientSession *BusySessions = NULL;

/* Interfaces we're listening on */
Interface *interfaces = NULL;
int NumInterfaces = 0;
int MaxInterfaces = 0;
int draining = 0;

/* The number of session slots */
size_t NumSessionSlots;

/* Maximum number of sessions per MAC address */
int MaxSessionsPerMac;

/* Number of active sessions */
size_t NumActiveSessions = 0;

/* Offset of first session */
size_t SessOffset = 0;

/* Event Selector */
EventSelector *event_selector;

/* Use Linux kernel-mode PPPoE? */
static int UseLinuxKernelModePPPoE = 0;

/* Requested max_ppp_payload */
static uint16_t max_ppp_payload = 0;

/* File with PPPD options */
static char *pppoptfile = NULL;

static char *pppd_path = PPPD_PATH;
static char *pppoe_path = PPPOE_PATH;

static char *motd_string = NULL;
static char *hurl_string = NULL;

static int Debug = 0;
static int CheckPoolSyntax = 0;

/* Synchronous mode */
static int Synchronous = 0;

/* Ignore PADI if no free sessions */
static int IgnorePADIIfNoFreeSessions = 0;

static int KidPipe[2] = {-1, -1};
static int LockFD = -1;

/* Random seed for cookie generation */
#define SEED_LEN 16
#define MD5_LEN 16
#define COOKIE_LEN (MD5_LEN + sizeof(pid_t)) /* Cookie is 16-byte MD5 + PID of server */

static unsigned char CookieSeed[SEED_LEN];

#define MAXLINE 512

/* Default interface if no -I option given */
#define DEFAULT_IF "eth0"

/* Access concentrator name */
char *ACName = NULL;

/* Options to pass to pppoe process */
char PppoeOptions[SMALLBUF] = "";

/* Our local IP address */
unsigned char LocalIP[IPV4ALEN] = {10, 0, 0, 1}; /* Counter optionally STARTS here */
unsigned char RemoteIP[IPV4ALEN] = {10, 67, 15, 1}; /* Counter STARTS here */

/* Do we increment local IP for each connection? */
int IncrLocalIP = 0;

/* Do we randomize session numbers? */
int RandomizeSessionNumbers = 0;

/* Do we pass the "unit" option to pppd?  (2.4 or greater) */
int PassUnitOptionToPPPD = 0;

static PPPoETag hostUniq;
static PPPoETag relayId;
static PPPoETag receivedCookie;
static PPPoETag requestedService;

#define HOSTNAMELEN 256

static int
count_sessions_from_mac(unsigned char *eth)
{
    int n=0;
    ClientSession *s = BusySessions;
    while(s) {
	if (!memcmp(eth, s->eth, ETH_ALEN)) n++;
	s = s->next;
    }
    return n;
}

/**********************************************************************
*Structures describing the CLI interface, and forward declarations.
***********************************************************************/
static int handle_set_drain(ClientConnection *client, const char* const* argv, int argi, void* pvt, void* clientpvt);

ControlCommand cmd_set[] = {
    { .command = "drain", .handler = handle_set_drain, },
    { .command = NULL, }
};

static int handle_status(ClientConnection *client, const char* const* argv, int argi, void* pvt, void* clientpvt);

ControlCommand cmd_status[] = {
    { .command = "status", .handler = handle_status, },
    { .command = NULL, }
};


ControlCommand cmd_root[] = {
    {
	.command = "set",
	.handler = control_socket_handle_command,
	.pvt = &cmd_set,
    },
    {
	.command = "show",
	.handler = control_socket_handle_command,
	.pvt = &cmd_status,
    },
    { .command = NULL, }
};

/**********************************************************************
*%FUNCTION: childHandler
*%ARGUMENTS:
* pid -- pid of child
* status -- exit status
* ses -- which session terminated
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called synchronously when a child dies.  Remove from busy list.
***********************************************************************/
static void
childHandler(pid_t pid, int status, void *s)
{
    ClientSession *session = s;

    /* Temporary structure for sending PADT's. */
    PPPoEConnection conn;

    memset(&conn, 0, sizeof(conn));
    conn.hostUniq = NULL;

    syslog(LOG_INFO,
	   "Session %u closed for client "
	   "%02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) on %s",
	   (unsigned int) ntohs(session->sess),
	   session->eth[0], session->eth[1], session->eth[2],
	   session->eth[3], session->eth[4], session->eth[5],
	   (int) session->peerip[0], (int) session->peerip[1],
	   (int) session->peerip[2], (int) session->peerip[3],
	   session->ethif->name);
    memcpy(conn.myEth, session->ethif->mac, ETH_ALEN);
    conn.discoverySocket = session->ethif->sock;
    conn.session = session->sess;
    memcpy(conn.peerEth, session->eth, ETH_ALEN);
    if (!(session->flags & FLAG_SENT_PADT)) {
	if (session->flags & FLAG_RECVD_PADT) {
	    sendPADT(&conn, "RP-PPPoE: Received PADT from peer");
	} else {
	    sendPADT(&conn, "RP-PPPoE: Child pppd process terminated");
	}
	session->flags |= FLAG_SENT_PADT;
    }

    session->serviceName = "";
    if (pppoe_free_session(session) < 0) {
	return;
    }

}

/**********************************************************************
*%FUNCTION: incrementIPAddress (static)
*%ARGUMENTS:
* addr -- a 4-byte array representing IP address
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Increments addr in-place
***********************************************************************/
static void
incrementIPAddress(unsigned char ip[IPV4ALEN])
{
    ip[3]++;
    if (!ip[3]) {
	ip[2]++;
	if (!ip[2]) {
	    ip[1]++;
	    if (!ip[1]) {
		ip[0]++;
	    }
	}
    }
}

/**********************************************************************
*%FUNCTION: ipIsNull (static)
*%ARGUMENTS:
* addr -- a 4-byte array representing IP address
*%RETURNS:
* 1 if ip represents 0.0.0.0, used to indicate delegation, 0 otherwise.
*%DESCRIPTION:
* Checks if ip is the null address used to indicate that IP allocation is
* to be delegated to pppd.
***********************************************************************/
static int
ipIsNull(const unsigned char ip[IPV4ALEN])
{
    int i;
    for (i = 0; i < IPV4ALEN; ++i)
	if (ip[i])
	    return 0;
    return 1;
}

/**********************************************************************
*%FUNCTION: killAllSessions
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills all pppd processes (and hence all PPPoE sessions)
***********************************************************************/
void
killAllSessions(void)
{
    ClientSession *sess = BusySessions;
    while(sess) {
	sess->funcs->stop(sess, "Shutting Down");
	sess = sess->next;
    }
}

/**********************************************************************
*%FUNCTION: parseAddressPool
*%ARGUMENTS:
* fname -- name of file containing IP address pool.
* install -- if true, install IP addresses in sessions.
*%RETURNS:
* Number of valid IP addresses found.
*%DESCRIPTION:
* Reads a list of IP addresses from a file.
***********************************************************************/
static int
parseAddressPool(char const *fname, int install)
{
    FILE *fp = fopen(fname, "r");
    int numAddrs = 0;
    unsigned int a, b, c, d;
    unsigned int e, f, g, h;
    char line[MAXLINE];

    if (!fp) {
	sysErr("Cannot open address pool file");
	exit(EXIT_FAILURE);
    }

    while (!feof(fp)) {
	if (!fgets(line, MAXLINE, fp)) {
	    break;
	}
	if ((sscanf(line, "%u.%u.%u.%u:%u.%u.%u.%u",
		    &a, &b, &c, &d, &e, &f, &g, &h) == 8) &&
	    a < 256 && b < 256 && c < 256 && d < 256 &&
	    e < 256 && f < 256 && g < 256 && h < 256) {

	    /* Both specified (local:remote) */
	    if (install) {
		Sessions[numAddrs].myip[0] = (unsigned char) a;
		Sessions[numAddrs].myip[1] = (unsigned char) b;
		Sessions[numAddrs].myip[2] = (unsigned char) c;
		Sessions[numAddrs].myip[3] = (unsigned char) d;
		Sessions[numAddrs].peerip[0] = (unsigned char) e;
		Sessions[numAddrs].peerip[1] = (unsigned char) f;
		Sessions[numAddrs].peerip[2] = (unsigned char) g;
		Sessions[numAddrs].peerip[3] = (unsigned char) h;
	    }
	    numAddrs++;
	} else if ((sscanf(line, "%u.%u.%u.%u-%u", &a, &b, &c, &d, &e) == 5) &&
		   a < 256 && b < 256 && c < 256 && d < 256 && e < 256) {
	    /* Remote specied as a.b.c.d-e.  Example: 1.2.3.4-8 yields:
	       1.2.3.4, 1.2.3.5, 1.2.3.6, 1.2.3.7, 1.2.3.8 */
	    /* Swap d and e so that e >= d */
	    if (e < d) {
		f = d;
		d = e;
		e = f;
	    }
	    if (install) {
		while (d <= e) {
		    Sessions[numAddrs].peerip[0] = (unsigned char) a;
		    Sessions[numAddrs].peerip[1] = (unsigned char) b;
		    Sessions[numAddrs].peerip[2] = (unsigned char) c;
		    Sessions[numAddrs].peerip[3] = (unsigned char) d;
		d++;
		numAddrs++;
		}
	    } else {
		numAddrs += (e-d) + 1;
	    }
	} else if ((sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) &&
		   a < 256 && b < 256 && c < 256 && d < 256) {
	    /* Only remote specified */
	    if (install) {
		Sessions[numAddrs].peerip[0] = (unsigned char) a;
		Sessions[numAddrs].peerip[1] = (unsigned char) b;
		Sessions[numAddrs].peerip[2] = (unsigned char) c;
		Sessions[numAddrs].peerip[3] = (unsigned char) d;
	    }
	    numAddrs++;
	}
    }
    fclose(fp);
    if (!numAddrs) {
	rp_fatal("No valid ip addresses found in pool file");
    }
    return numAddrs;
}

/**********************************************************************
*%FUNCTION: parsePADITags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADI packet
***********************************************************************/
void
parsePADITags(uint16_t type, uint16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_PPP_MAX_PAYLOAD:
	if (len == sizeof(max_ppp_payload)) {
	    memcpy(&max_ppp_payload, data, sizeof(max_ppp_payload));
	    max_ppp_payload = ntohs(max_ppp_payload);
	    if (max_ppp_payload <= ETH_PPPOE_MTU) {
		max_ppp_payload = 0;
	    }
	}
	break;
    case TAG_SERVICE_NAME:
	/* Copy requested service name */
	requestedService.type = htons(type);
	requestedService.length = htons(len);
	memcpy(requestedService.payload, data, len);
	break;
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_HOST_UNIQ:
	hostUniq.type = htons(type);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, data, len);
	break;
    }
}

/**********************************************************************
*%FUNCTION: parsePADRTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADR packet
***********************************************************************/
void
parsePADRTags(uint16_t type, uint16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_PPP_MAX_PAYLOAD:
	if (len == sizeof(max_ppp_payload)) {
	    memcpy(&max_ppp_payload, data, sizeof(max_ppp_payload));
	    max_ppp_payload = ntohs(max_ppp_payload);
	    if (max_ppp_payload <= ETH_PPPOE_MTU) {
		max_ppp_payload = 0;
	    }
	}
	break;
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_HOST_UNIQ:
	hostUniq.type = htons(type);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, data, len);
	break;
    case TAG_AC_COOKIE:
	receivedCookie.type = htons(type);
	receivedCookie.length = htons(len);
	memcpy(receivedCookie.payload, data, len);
	break;
    case TAG_SERVICE_NAME:
	requestedService.type = htons(type);
	requestedService.length = htons(len);
	memcpy(requestedService.payload, data, len);
	break;
    }
}

/**********************************************************************
*%FUNCTION: fatalSys
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to stderr and syslog and exits.
***********************************************************************/
void
fatalSys(char const *str)
{
    printErr("%s: %s", str, strerror(errno));
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: sysErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to syslog.
***********************************************************************/
void
sysErr(char const *str)
{
    printErr("%.256s: %.256s", str, strerror(errno));
}

/**********************************************************************
*%FUNCTION: rp_fatal
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog and exits.
***********************************************************************/
void
rp_fatal(char const *str)
{
    printErr("%s", str);
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: genCookie
*%ARGUMENTS:
* peerEthAddr -- peer Ethernet address (6 bytes)
* myEthAddr -- my Ethernet address (6 bytes)
* seed -- random cookie seed to make things tasty (16 bytes)
* cookie -- buffer which is filled with server PID and
*           md5 sum of previous items
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Forms the md5 sum of peer MAC address, our MAC address and seed, useful
* in a PPPoE Cookie tag.
***********************************************************************/
void
genCookie(unsigned char const *peerEthAddr,
	  unsigned char const *myEthAddr,
	  unsigned char const *seed,
	  unsigned char *cookie)
{
    struct MD5Context ctx;
    pid_t pid = getpid();

    MD5Init(&ctx);
    MD5Update(&ctx, peerEthAddr, ETH_ALEN);
    MD5Update(&ctx, myEthAddr, ETH_ALEN);
    MD5Update(&ctx, seed, SEED_LEN);
    MD5Final(cookie, &ctx);
    memcpy(cookie+MD5_LEN, &pid, sizeof(pid));
}

/**********************************************************************
*%FUNCTION: processPADI
*%ARGUMENTS:
* ethif -- Interface
* packet -- PPPoE PADI packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADO packet back to client
***********************************************************************/
void
processPADI(Interface *ethif, PPPoEPacket *packet, int len)
{
    PPPoEPacket pado;
    PPPoETag acname;
    PPPoETag servname;
    PPPoETag cookie;
    size_t acname_len;
    unsigned char *cursor = pado.payload;
    uint16_t plen;

    int sock = ethif->sock;
    int i;
    int ok = 0;
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADI's if we're draining the server */
    if (draining != DRAIN_OFF) {
	syslog(LOG_ERR, "PADI ignored due to server draining.");
	return;
    }

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	syslog(LOG_ERR, "PADI packet from non-unicast source address");
	return;
    }

    /* If no free sessions and "-i" flag given, ignore */
    if (IgnorePADIIfNoFreeSessions && !FreeSessions) {
	syslog(LOG_INFO, "PADI ignored - No free session slots available");
	return;
    }

    /* If number of sessions per MAC is limited, check here and don't
       send PADO if already max number of sessions. */
    if (MaxSessionsPerMac) {
	if (count_sessions_from_mac(packet->ethHdr.h_source) >= MaxSessionsPerMac) {
	    syslog(LOG_INFO, "PADI: Client %02x:%02x:%02x:%02x:%02x:%02x attempted to create more than %d session(s)",
		   packet->ethHdr.h_source[0],
		   packet->ethHdr.h_source[1],
		   packet->ethHdr.h_source[2],
		   packet->ethHdr.h_source[3],
		   packet->ethHdr.h_source[4],
		   packet->ethHdr.h_source[5],
		   MaxSessionsPerMac);
	    return;
	}
    }

    acname.type = htons(TAG_AC_NAME);
    acname_len = strlen(ACName);
    acname.length = htons(acname_len);
    memcpy(acname.payload, ACName, acname_len);

    relayId.type = 0;
    hostUniq.type = 0;
    requestedService.type = 0;
    max_ppp_payload = 0;

    parsePacket(packet, parsePADITags, NULL);

    /* If PADI specified non-default service name, and we do not offer
       that service, DO NOT send PADO */
    if (requestedService.type) {
	int slen = ntohs(requestedService.length);
	if (slen) {
	    for (i=0; i<NumServiceNames; i++) {
		if (slen == strlen(ServiceNames[i]) &&
		    !memcmp(ServiceNames[i], &requestedService.payload, slen)) {
		    ok = 1;
		    break;
		}
	    }
	} else {
	    ok = 1;		/* Default service requested */
	}
    } else {
	ok = 1;			/* No Service-Name tag in PADI */
    }

    if (!ok) {
	/* PADI asked for unsupported service */
	return;
    }

    /* Generate a cookie */
    cookie.type = htons(TAG_AC_COOKIE);
    cookie.length = htons(COOKIE_LEN);
    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookie.payload);

    /* Construct a PADO packet */
    memcpy(pado.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pado.ethHdr.h_source, myAddr, ETH_ALEN);
    pado.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pado.vertype = PPPOE_VER_TYPE(1, 1);
    pado.code = CODE_PADO;
    pado.session = 0;
    plen = TAG_HDR_SIZE + acname_len;

    CHECK_ROOM(cursor, pado.payload, acname_len+TAG_HDR_SIZE);
    memcpy(cursor, &acname, acname_len + TAG_HDR_SIZE);
    cursor += acname_len + TAG_HDR_SIZE;

    /* If we asked for an MTU, handle it */
    if (max_ppp_payload > ETH_PPPOE_MTU && ethif->mtu > 0) {
	/* Shrink payload to fit */
	if (max_ppp_payload > ethif->mtu - TOTAL_OVERHEAD) {
	    max_ppp_payload = ethif->mtu - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_JUMBO_LEN - TOTAL_OVERHEAD) {
	    max_ppp_payload = ETH_JUMBO_LEN - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_PPPOE_MTU) {
	    PPPoETag maxPayload;
	    uint16_t mru = htons(max_ppp_payload);
	    maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
	    maxPayload.length = htons(sizeof(mru));
	    memcpy(maxPayload.payload, &mru, sizeof(mru));
	    CHECK_ROOM(cursor, pado.payload, sizeof(mru) + TAG_HDR_SIZE);
	    memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
	    cursor += sizeof(mru) + TAG_HDR_SIZE;
	    plen += sizeof(mru) + TAG_HDR_SIZE;
	}
    }
    /* If no service-names specified on command-line, just send default
       zero-length name.  Otherwise, add all service-name tags */
    servname.type = htons(TAG_SERVICE_NAME);
    if (!NumServiceNames) {
	servname.length = 0;
	CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE);
	memcpy(cursor, &servname, TAG_HDR_SIZE);
	cursor += TAG_HDR_SIZE;
	plen += TAG_HDR_SIZE;
    } else {
	for (i=0; i<NumServiceNames; i++) {
	    int slen = strlen(ServiceNames[i]);
	    servname.length = htons(slen);
	    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE+slen);
	    memcpy(cursor, &servname, TAG_HDR_SIZE);
	    memcpy(cursor+TAG_HDR_SIZE, ServiceNames[i], slen);
	    cursor += TAG_HDR_SIZE+slen;
	    plen += TAG_HDR_SIZE+slen;
	}
    }

    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE + COOKIE_LEN);
    memcpy(cursor, &cookie, TAG_HDR_SIZE + COOKIE_LEN);
    cursor += TAG_HDR_SIZE + COOKIE_LEN;
    plen += TAG_HDR_SIZE + COOKIE_LEN;

    if (relayId.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(hostUniq.length)+TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pado.length = htons(plen);
    sendPacket(NULL, sock, &pado, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: processPADT
*%ARGUMENTS:
* ethif -- interface
* packet -- PPPoE PADT packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills session whose session-ID is in PADT packet.
***********************************************************************/
void
processPADT(Interface *ethif, PPPoEPacket *packet, int len)
{
    size_t i;

    unsigned char *myAddr = ethif->mac;

    /* Ignore PADT's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    /* Get session's index */
    i = ntohs(packet->session) - 1 - SessOffset;
    if (i >= NumSessionSlots) return;
    if (Sessions[i].sess != packet->session) {
	syslog(LOG_ERR, "Session index %u doesn't match session number %u",
	       (unsigned int) i, (unsigned int) ntohs(packet->session));
	return;
    }


    /* If source MAC does not match, do not kill session */
    if (memcmp(packet->ethHdr.h_source, Sessions[i].eth, ETH_ALEN)) {
        if (!Sessions[i].eth[0] &&
            !Sessions[i].eth[1] &&
            !Sessions[i].eth[2] &&
            !Sessions[i].eth[3] &&
            !Sessions[i].eth[4] &&
            !Sessions[i].eth[5]) {
            syslog(LOG_INFO, "PADT for closed session %u received from "
                   "%02X:%02X:%02X:%02X:%02X:%02X",
                   (unsigned int) ntohs(packet->session),
                   packet->ethHdr.h_source[0],
                   packet->ethHdr.h_source[1],
                   packet->ethHdr.h_source[2],
                   packet->ethHdr.h_source[3],
                   packet->ethHdr.h_source[4],
                   packet->ethHdr.h_source[5]);
        } else {
            syslog(LOG_WARNING, "PADT for session %u received from "
                   "%02X:%02X:%02X:%02X:%02X:%02X; should be from "
                   "%02X:%02X:%02X:%02X:%02X:%02X",
                   (unsigned int) ntohs(packet->session),
                   packet->ethHdr.h_source[0],
                   packet->ethHdr.h_source[1],
                   packet->ethHdr.h_source[2],
                   packet->ethHdr.h_source[3],
                   packet->ethHdr.h_source[4],
                   packet->ethHdr.h_source[5],
                   Sessions[i].eth[0],
                   Sessions[i].eth[1],
                   Sessions[i].eth[2],
                   Sessions[i].eth[3],
                   Sessions[i].eth[4],
                   Sessions[i].eth[5]);
        }
	return;
    }
    Sessions[i].flags |= FLAG_RECVD_PADT;
    parsePacket(packet, parseLogErrs, NULL);
    Sessions[i].funcs->stop(&Sessions[i], "Received PADT");
}

/**********************************************************************
*%FUNCTION: processPADR
*%ARGUMENTS:
* ethif -- Ethernet interface
* packet -- PPPoE PADR packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADS packet back to client and starts a PPP session if PADR
* packet is OK.
***********************************************************************/
void
processPADR(Interface *ethif, PPPoEPacket *packet, int len)
{
    unsigned char cookieBuffer[COOKIE_LEN];
    ClientSession *cliSession;
    pid_t child;
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    uint16_t plen;
    int i;
    int sock = ethif->sock;
    unsigned char *myAddr = ethif->mac;
    int slen = 0;
    char const *serviceName = NULL;

    /* Temporary structure for sending PADM's. */
    PPPoEConnection conn;

    /* Initialize some globals */
    relayId.type = 0;
    hostUniq.type = 0;
    receivedCookie.type = 0;
    requestedService.type = 0;

    /* Ignore PADR's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    /* Ignore PADR's from non-unicast addresses */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	syslog(LOG_ERR, "PADR packet from non-unicast source address");
	return;
    }

    /* If number of sessions per MAC is limited, check here and don't
       send PADS if already max number of sessions. */
    if (MaxSessionsPerMac) {
	if (count_sessions_from_mac(packet->ethHdr.h_source) >= MaxSessionsPerMac) {
	    syslog(LOG_INFO, "PADR: Client %02x:%02x:%02x:%02x:%02x:%02x attempted to create more than %d session(s)",
		   packet->ethHdr.h_source[0],
		   packet->ethHdr.h_source[1],
		   packet->ethHdr.h_source[2],
		   packet->ethHdr.h_source[3],
		   packet->ethHdr.h_source[4],
		   packet->ethHdr.h_source[5],
		   MaxSessionsPerMac);
	    return;
	}
    }

    max_ppp_payload = 0;
    parsePacket(packet, parsePADRTags, NULL);

    /* Check that everything's cool */
    if (!receivedCookie.type) {
	/* Drop it -- do not send error PADS */
	return;
    }

    /* Is cookie kosher? */
    if (receivedCookie.length != htons(COOKIE_LEN)) {
	/* Drop it -- do not send error PADS */
	return;
    }

    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookieBuffer);
    if (memcmp(receivedCookie.payload, cookieBuffer, COOKIE_LEN)) {
	/* Drop it -- do not send error PADS */
	return;
    }

    /* Check service name */
    if (!requestedService.type) {
	syslog(LOG_ERR, "Received PADR packet with no SERVICE_NAME tag");
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Server: No service name tag");
	return;
    }

    slen = ntohs(requestedService.length);
    if (slen) {
	/* Check supported services */
	for(i=0; i<NumServiceNames; i++) {
	    if (slen == strlen(ServiceNames[i]) &&
		!memcmp(ServiceNames[i], &requestedService.payload, slen)) {
		serviceName = ServiceNames[i];
		break;
	    }
	}

	if (!serviceName) {
	    syslog(LOG_ERR, "Received PADR packet asking for unsupported service %.*s", (int) ntohs(requestedService.length), requestedService.payload);
	    sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
			  TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Server: Invalid service name tag");
	    return;
	}
    } else {
	serviceName = "";
    }

    /* Looks cool... find a slot for the session */
    cliSession = pppoe_alloc_session();
    if (!cliSession) {
	syslog(LOG_ERR, "No client slots available (%02x:%02x:%02x:%02x:%02x:%02x)",
	       (unsigned int) packet->ethHdr.h_source[0],
	       (unsigned int) packet->ethHdr.h_source[1],
	       (unsigned int) packet->ethHdr.h_source[2],
	       (unsigned int) packet->ethHdr.h_source[3],
	       (unsigned int) packet->ethHdr.h_source[4],
	       (unsigned int) packet->ethHdr.h_source[5]);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Server: No client slots available");
	return;
    }

    /* Set up client session peer Ethernet address */
    memcpy(cliSession->eth, packet->ethHdr.h_source, ETH_ALEN);
    cliSession->ethif = ethif;
    cliSession->flags = 0;
    cliSession->funcs = &DefaultSessionFunctionTable;
    cliSession->startTime = time(NULL);
    cliSession->serviceName = serviceName;

    /* Create child process, send PADS packet back */
    child = fork();
    if (child < 0) {
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Server: Unable to start session process");
	pppoe_free_session(cliSession);
	return;
    }
    if (child != 0) {
	/* In the parent process.  Mark pid in session slot */
	cliSession->pid = child;
	Event_HandleChildExit(event_selector, child,
			      childHandler, cliSession);
	return;
    }

    /* In the child process */

    /* Reset signal handlers to default */
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);

    /* Close all file descriptors except for socket */
    closelog();
    if (LockFD >= 0) close(LockFD);
    for (i=0; i<CLOSEFD; i++) {
	if (i != sock) {
	    close(i);
	}
    }

    openlog("pppoe-server", LOG_PID, LOG_DAEMON);
    /* pppd has a nasty habit of killing all processes in its process group.
       Start a new session to stop pppd from killing us! */
    setsid();

    /* Send PADS and Start pppd */
    memcpy(pads.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, myAddr, ETH_ALEN);
    pads.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pads.vertype = PPPOE_VER_TYPE(1, 1);
    pads.code = CODE_PADS;

    pads.session = cliSession->sess;
    plen = 0;

    /* Copy requested service name tag back in.  If requested-service name
       length is zero, and we have non-zero services, use first service-name
       as default */
    if (!slen && NumServiceNames) {
	slen = strlen(ServiceNames[0]);
	memcpy(&requestedService.payload, ServiceNames[0], slen);
	requestedService.length = htons(slen);
    }
    memcpy(cursor, &requestedService, TAG_HDR_SIZE+slen);
    cursor += TAG_HDR_SIZE+slen;
    plen += TAG_HDR_SIZE+slen;

    /* If we asked for an MTU, handle it */
    if (max_ppp_payload > ETH_PPPOE_MTU && ethif->mtu > 0) {
	/* Shrink payload to fit */
	if (max_ppp_payload > ethif->mtu - TOTAL_OVERHEAD) {
	    max_ppp_payload = ethif->mtu - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_JUMBO_LEN - TOTAL_OVERHEAD) {
	    max_ppp_payload = ETH_JUMBO_LEN - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_PPPOE_MTU) {
	    PPPoETag maxPayload;
	    uint16_t mru = htons(max_ppp_payload);
	    maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
	    maxPayload.length = htons(sizeof(mru));
	    memcpy(maxPayload.payload, &mru, sizeof(mru));
	    CHECK_ROOM(cursor, pads.payload, sizeof(mru) + TAG_HDR_SIZE);
	    memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
	    cursor += sizeof(mru) + TAG_HDR_SIZE;
	    plen += sizeof(mru) + TAG_HDR_SIZE;
	    cliSession->requested_mtu = max_ppp_payload;
	}
    }

    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pads.length = htons(plen);
    sendPacket(NULL, sock, &pads, (int) (plen + HDR_SIZE));

    if (hurl_string || motd_string) {
	memset(&conn, 0, sizeof(conn));
	conn.hostUniq = NULL;

	memcpy(conn.myEth, cliSession->ethif->mac, ETH_ALEN);
	conn.discoverySocket = sock;
	conn.session = cliSession->sess;
	memcpy(conn.peerEth, cliSession->eth, ETH_ALEN);
	if (hurl_string != NULL)
	    sendHURLorMOTM(&conn, hurl_string, TAG_HURL);
	if (motd_string != NULL)
	    sendHURLorMOTM(&conn, motd_string, TAG_MOTM);
    }
    /* Close sock; don't need it any more */
    close(sock);

    startPPPD(cliSession);
}

/**********************************************************************
*%FUNCTION: pppoe_terminate
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Call this in order to terminate the server.
***********************************************************************/
static __attribute__((noreturn)) void
pppoe_terminate(void)
{
    killAllSessions();
    exit(EXIT_SUCCESS);
}

/**********************************************************************
*%FUNCTION: termHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGTERM or SIGINT.  Causes all sessions to be killed!
***********************************************************************/
static void
termHandler(int sig)
{
    syslog(LOG_INFO,
	   "Terminating on signal %d -- killing all PPPoE sessions",
	   sig);
    pppoe_terminate();
}

/**********************************************************************
*%FUNCTION: usage
*%ARGUMENTS:
* argv0 -- argv[0] from main
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints usage instructions
***********************************************************************/
void
usage(char const *argv0)
{
    fprintf(stderr, "Usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "   -I if_name     -- Specify interface (default %s.)\n",
	    DEFAULT_IF);
    fprintf(stderr, "   -T timeout     -- Specify inactivity timeout in seconds.\n");
    fprintf(stderr, "   -C name        -- Set access concentrator name.\n");
    fprintf(stderr, "   -m MSS         -- Clamp incoming and outgoing MSS options.\n");
    fprintf(stderr, "   -L ip          -- Set local IP address.\n");
    fprintf(stderr, "   -l             -- Increment local IP address for each session.\n");
    fprintf(stderr, "   -R ip          -- Set start address of remote IP pool.\n");
    fprintf(stderr, "   -S name        -- Advertise specified service-name.\n");
    fprintf(stderr, "   -O fname       -- Use PPPD options from specified file\n");
    fprintf(stderr, "                     (default %s).\n", PPPOE_SERVER_OPTIONS);
    fprintf(stderr, "   -p fname       -- Obtain IP address pool from specified file.\n");
    fprintf(stderr, "   -N num         -- Allow 'num' concurrent sessions.\n");
    fprintf(stderr, "   -o offset      -- Assign session numbers starting at offset+1.\n");
    fprintf(stderr, "   -f disc:sess   -- Set Ethernet frame types (hex).\n");
    fprintf(stderr, "   -s             -- Use synchronous PPP mode.\n");
    fprintf(stderr, "   -X pidfile     -- Write PID and lock pidfile.\n");
    fprintf(stderr, "   -q /path/pppd  -- Specify full path to pppd.\n");
    fprintf(stderr, "   -Q /path/pppoe -- Specify full path to pppoe.\n");
    fprintf(stderr, "   -k             -- Use kernel-mode PPPoE.\n");
    fprintf(stderr, "   -g path        -- Specify full path to plugin (default %s)\n", PLUGIN_PATH);
    fprintf(stderr, "   -u             -- Pass 'unit' option to pppd.\n");
    fprintf(stderr, "   -r             -- Randomize session numbers.\n");
    fprintf(stderr, "   -d             -- Debug session creation.\n");
    fprintf(stderr, "   -x n           -- Limit to 'n' sessions/MAC address.\n");
    fprintf(stderr, "   -P             -- Check pool file for correctness and exit.\n");
    fprintf(stderr, "   -i             -- Ignore PADI if no free sessions.\n");
    fprintf(stderr, "   -M msg         -- Send MSG in a MOTM tag in PADM packet after PADS.\n");
    fprintf(stderr, "   -H url         -- Send URL in a HURL tag in PADM packet after PADS.\n");
    fprintf(stderr, "   -h             -- Print usage information.\n\n");
    fprintf(stderr, "PPPoE-Server Version %s, Copyright (C) 2001-2009 Roaring Penguin Software Inc.\n", RP_VERSION);
    fprintf(stderr, "                     %*s  Copyright (C) 2018-2023 Dianne Skoll\n", (int) strlen(RP_VERSION), "");
    fprintf(stderr, "PPPoE-Server comes with ABSOLUTELY NO WARRANTY.\n");
    fprintf(stderr, "This is free software, and you are welcome to redistribute it\n");
    fprintf(stderr, "under the terms of the GNU General Public License, version 2\n");
    fprintf(stderr, "or (at your option) any later version.\n");
    fprintf(stderr, "https://dianne.skoll.ca/projects/rp-pppoe/\n");
}

/**********************************************************************
*%FUNCTION: main
*%ARGUMENTS:
* argc, argv -- usual suspects
*%RETURNS:
* Exit status
*%DESCRIPTION:
* Main program of PPPoE server
***********************************************************************/
int
main(int argc, char **argv)
{

    FILE *fp;
    int i, j;
    int opt;
    int d[IPV4ALEN];
    int beDaemon = 1;
    int found;
    unsigned int discoveryType, sessionType;
    char *addressPoolFname = NULL;
    char *pidfile = NULL;
    char *unix_control = NULL;
    char c;
    char const *s;
    int cookie_ok = 0;

    char const *options = "X:ix:hI:C:L:R:T:m:FN:f:O:o:skp:lrudPS:q:Q:H:M:U:g:";

    if (getuid() != geteuid() ||
	getgid() != getegid()) {
	fprintf(stderr, "SECURITY WARNING: pppoe-server will NOT run suid or sgid.  Fix your installation.\n");
	exit(EXIT_FAILURE);
    }

    /* Initialize syslog */
    openlog("pppoe-server", LOG_PID, LOG_DAEMON);

    MaxInterfaces = INIT_INTERFACES;
    interfaces = malloc(sizeof(*interfaces) * INIT_INTERFACES);
    if (!interfaces) {
	fprintf(stderr, "Out of memory allocating initial interfaces.\n");
	exit(EXIT_FAILURE);
    }

    /* Default number of session slots */
    NumSessionSlots = DEFAULT_MAX_SESSIONS;
    MaxSessionsPerMac = 0; /* No limit */
    NumActiveSessions = 0;

    /* Parse command-line options */
    while((opt = getopt(argc, argv, options)) != -1) {
	switch(opt) {
	case 'i':
	    IgnorePADIIfNoFreeSessions = 1;
	    break;
	case 'x':
	    if (sscanf(optarg, "%d", &MaxSessionsPerMac) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    if (MaxSessionsPerMac < 0) {
		MaxSessionsPerMac = 0;
	    }
	    break;

	case 'k':
	    UseLinuxKernelModePPPoE = 1;
	    break;
        case 'g':
            plugin_path = strdup(optarg);
            if (!plugin_path) {
                fprintf(stderr, "Out of memory\n");
                exit(EXIT_FAILURE);
            }
            break;
	case 'S':
	    if (NumServiceNames == MAX_SERVICE_NAMES) {
		fprintf(stderr, "Too many '-S' options (%d max)",
			MAX_SERVICE_NAMES);
		exit(EXIT_FAILURE);
	    }

            /* Service names can only be [-_.A-Za-z0-9/] for shell-escaping
               safety reasons */
            for (s=optarg; *s; s++) {
                if (!strchr("-_.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/", *s)) {
                    fprintf(stderr, "Illegal character `%c' in service-name: Must be A-Z, a-z, 0-9 or one of ./-_\n", *s);
                    exit(EXIT_FAILURE);
                }
            }

	    ServiceNames[NumServiceNames] = strdup(optarg);
	    if (!ServiceNames[NumServiceNames]) {
		fprintf(stderr, "Out of memory\n");
		exit(EXIT_FAILURE);
	    }
	    NumServiceNames++;
	    break;
	case 'q':
	    pppd_path = strdup(optarg);
	    if (!pppd_path) {
		fprintf(stderr, "Out of memory\n");
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'Q':
	    pppoe_path = strdup(optarg);
	    if (!pppoe_path) {
		fprintf(stderr, "Out of memory\n");
		exit(EXIT_FAILURE);
	    }
	    break;

	case 'M':
	    if (motd_string) {
		free(motd_string);
		motd_string = NULL;
	    }
	    motd_string = strdup(optarg);
	    if (!motd_string) {
		fprintf(stderr, "Out of memory\n");
		exit(EXIT_FAILURE);
	    }
	    break;

	case 'H':
	    if (hurl_string) {
		free(hurl_string);
		hurl_string = NULL;
	    }
	    hurl_string = strdup(optarg);
	    if (!hurl_string) {
		fprintf(stderr, "Out of memory\n");
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'd':
	    Debug = 1;
	    break;
	case 'P':
	    CheckPoolSyntax = 1;
	    break;
	case 'u':
	    PassUnitOptionToPPPD = 1;
	    break;

	case 'r':
	    RandomizeSessionNumbers = 1;
	    break;

	case 'l':
	    IncrLocalIP = 1;
	    break;

	case 'p':
	    SET_STRING(addressPoolFname, optarg);
	    break;

	case 'X':
	    SET_STRING(pidfile, optarg);
	    break;
	case 's':
	    Synchronous = 1;
	    /* Pass the Synchronous option on to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -s");
	    break;

	case 'f':
	    if (sscanf(optarg, "%x:%x", &discoveryType, &sessionType) != 2) {
		fprintf(stderr, "Illegal argument to -f: Should be disc:sess in hex\n");
		exit(EXIT_FAILURE);
	    }
	    Eth_PPPOE_Discovery = (uint16_t) discoveryType;
	    Eth_PPPOE_Session   = (uint16_t) sessionType;
	    /* This option gets passed to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -%c %s", opt, optarg);
	    break;

	case 'F':
	    beDaemon = 0;
	    break;

	case 'N':
	    if (sscanf(optarg, "%d", &opt) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    if (opt <= 0) {
		fprintf(stderr, "-N: Value must be positive\n");
		exit(EXIT_FAILURE);
	    }
	    NumSessionSlots = opt;
	    break;

	case 'O':
	    SET_STRING(pppoptfile, optarg);
	    break;

	case 'o':
	    if (sscanf(optarg, "%d", &opt) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    if (opt < 0) {
		fprintf(stderr, "-o: Value must be non-negative\n");
		exit(EXIT_FAILURE);
	    }
	    SessOffset = (size_t) opt;
	    break;

	case 'I':
	    if (NumInterfaces >= MaxInterfaces) {
		MaxInterfaces *= 2;
		interfaces = realloc(interfaces, sizeof(*interfaces) * MaxInterfaces);
		if (!interfaces) {
		    fprintf(stderr, "Memory allocation failure trying to increase MaxInterfaces to %d\n",
			    MaxInterfaces);
		    exit(EXIT_FAILURE);
		}
	    }
	    found = 0;
	    for (i=0; i<NumInterfaces; i++) {
		if (!strncmp(interfaces[i].name, optarg, IFNAMSIZ)) {
		    found = 1;
		    break;
		}
	    }
	    if (!found) {
		memset(&interfaces[NumInterfaces], 0, sizeof(*interfaces));
		strncpy(interfaces[NumInterfaces].name, optarg, IFNAMSIZ);
		NumInterfaces++;
	    }
	    break;

	case 'C':
	    SET_STRING(ACName, optarg);
	    break;

	case 'L':
	case 'R':
	    /* Get local/remote IP address */
	    if (sscanf(optarg, "%d.%d.%d.%d", &d[0], &d[1], &d[2], &d[3]) != 4) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    for (i=0; i<IPV4ALEN; i++) {
		if (d[i] < 0 || d[i] > 255) {
		    usage(argv[0]);
		    exit(EXIT_FAILURE);
		}
		if (opt == 'L') {
		    LocalIP[i] = (unsigned char) d[i];
		} else {
		    RemoteIP[i] = (unsigned char) d[i];
		}
	    }
	    break;

	case 'T':
	case 'm':
	    /* These just get passed to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -%c %s", opt, optarg);
	    break;

	case 'U':
	    SET_STRING(unix_control, optarg);
	    break;

	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);
	}
    }

    if (!pppoptfile) {
	pppoptfile = PPPOE_SERVER_OPTIONS;
    }

    if (!NumInterfaces) {
	strcpy(interfaces[0].name, DEFAULT_IF);
	NumInterfaces = 1;
    }

    if (!ACName) {
	ACName = malloc(HOSTNAMELEN);
	if (gethostname(ACName, HOSTNAMELEN) < 0) {
	    fatalSys("gethostname");
	}
    }

    /* If address pool filename given, count number of addresses */
    if (addressPoolFname) {
	NumSessionSlots = parseAddressPool(addressPoolFname, 0);
	if (CheckPoolSyntax) {
	    printf("%lu\n", (unsigned long) NumSessionSlots);
	    exit(EXIT_SUCCESS);
	}
    }

    /* Max 65534 - SessOffset sessions */
    if (NumSessionSlots + SessOffset > 65534) {
	fprintf(stderr, "-N and -o options must add up to at most 65534\n");
	exit(EXIT_FAILURE);
    }

    /* Allocate memory for sessions */
    Sessions = calloc(NumSessionSlots, sizeof(ClientSession));
    if (!Sessions) {
	rp_fatal("Cannot allocate memory for session slots");
    }

    /* Fill in local addresses first (let pool file override later */
    for (i=0; i<NumSessionSlots; i++) {
	memcpy(Sessions[i].myip, LocalIP, sizeof(LocalIP));
	if (IncrLocalIP) {
	    incrementIPAddress(LocalIP);
	}
    }

    /* Fill in remote IP addresses from pool (may also overwrite local ips) */
    if (addressPoolFname) {
	(void) parseAddressPool(addressPoolFname, 1);
    }

    /* For testing -- generate sequential remote IP addresses */
    for (i=0; i<NumSessionSlots; i++) {
	Sessions[i].pid = 0;
	Sessions[i].funcs = &DefaultSessionFunctionTable;
	Sessions[i].sess = htons(i+1+SessOffset);

	if (!addressPoolFname && !ipIsNull(RemoteIP)) {
	    memcpy(Sessions[i].peerip, RemoteIP, sizeof(RemoteIP));
	    incrementIPAddress(RemoteIP);
	}
    }

    /* Initialize our random cookie.  Try /dev/urandom; if that fails,
       use PID and rand() */
    fp = fopen("/dev/urandom", "r");
    if (fp) {
	unsigned int x;
	cookie_ok = 1;
	if (fread(&x, 1, sizeof(x), fp) < sizeof(x)) cookie_ok = 0;
	srand(x);
	if (fread(&CookieSeed, 1, SEED_LEN, fp) < SEED_LEN) cookie_ok = 0;
	fclose(fp);
    }
    if (!cookie_ok) {
	srand((unsigned int) getpid() * (unsigned int) time(NULL));
	CookieSeed[0] = getpid() & 0xFF;
	CookieSeed[1] = (getpid() >> 8) & 0xFF;
	for (i=2; i<SEED_LEN; i++) {
	    CookieSeed[i] = (rand() >> (i % 9)) & 0xFF;
	}
    }

    if (RandomizeSessionNumbers) {
	int *permutation;
	int tmp;
	permutation = malloc(sizeof(int) * NumSessionSlots);
	if (!permutation) {
	    fprintf(stderr, "Could not allocate memory to randomize session numbers\n");
	    exit(EXIT_FAILURE);
	}
	for (i=0; i<NumSessionSlots; i++) {
	    permutation[i] = i;
	}
	for (i=0; i<NumSessionSlots-1; i++) {
	    j = i + rand() % (NumSessionSlots - i);
	    if (j != i) {
		tmp = permutation[j];
		permutation[j] = permutation[i];
		permutation[i] = tmp;
	    }
	}
	/* Link sessions together */
	FreeSessions = &Sessions[permutation[0]];
	LastFreeSession = &Sessions[permutation[NumSessionSlots-1]];
	for (i=0; i<NumSessionSlots-1; i++) {
	    Sessions[permutation[i]].next = &Sessions[permutation[i+1]];
	}
	Sessions[permutation[NumSessionSlots-1]].next = NULL;
	free(permutation);
    } else {
	/* Link sessions together */
	FreeSessions = &Sessions[0];
	LastFreeSession = &Sessions[NumSessionSlots - 1];
	for (i=0; i<NumSessionSlots-1; i++) {
	    Sessions[i].next = &Sessions[i+1];
	}
	Sessions[NumSessionSlots-1].next = NULL;
    }

    if (Debug) {
	/* Dump session array and exit */
	ClientSession *ses = FreeSessions;
	while(ses) {
	    printf("Session %u local %d.%d.%d.%d remote %d.%d.%d.%d\n",
		   (unsigned int) (ntohs(ses->sess)),
		   ses->myip[0], ses->myip[1],
		   ses->myip[2], ses->myip[3],
		   ses->peerip[0], ses->peerip[1],
		   ses->peerip[2], ses->peerip[3]);
	    ses = ses->next;
	}
	exit(EXIT_SUCCESS);
    }

    /* Open all the interfaces */
    for (i=0; i<NumInterfaces; i++) {
	interfaces[i].mtu = 0;
	interfaces[i].sock = openInterface(interfaces[i].name, Eth_PPPOE_Discovery, interfaces[i].mac, &interfaces[i].mtu);
    }

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    /* Create event selector */
    event_selector = Event_CreateSelector();
    if (!event_selector) {
	rp_fatal("Could not create EventSelector -- probably out of memory");
    }

    if (unix_control && control_socket_init(event_selector, unix_control, cmd_root) != 0)
	rp_fatal("control_socket_init failed");

    /* Create event handler for each interface */
    for (i = 0; i<NumInterfaces; i++) {
	interfaces[i].eh = Event_AddHandler(event_selector,
					    interfaces[i].sock,
					    EVENT_FLAG_READABLE,
					    InterfaceHandler,
					    &interfaces[i]);
	if (!interfaces[i].eh) {
	    rp_fatal("Event_AddHandler failed");
	}
    }

    /* Daemonize -- UNIX Network Programming, Vol. 1, Stevens */
    if (beDaemon) {
	if (pipe(KidPipe) < 0) {
	    fatalSys("pipe");
	}
	i = fork();
	if (i < 0) {
	    fatalSys("fork");
	} else if (i != 0) {
	    /* parent */
	    close(KidPipe[1]);
	    KidPipe[1] = -1;
	    /* Wait for child to give the go-ahead */
	    while(1) {
		int r = read(KidPipe[0], &c, 1);
		if (r == 0) {
		    fprintf(stderr, "EOF from child - something went wrong; please check logs.\n");
		    exit(EXIT_FAILURE);
		}
		if (r < 0) {
		    if (errno == EINTR) continue;
		    fatalSys("read");
		}
		break;
	    }

	    if (c == 'X') {
		exit(EXIT_SUCCESS);
	    }

	    /* Read error message from child */
	    while (1) {
		int r = read(KidPipe[0], &c, 1);
		if (r == 0) exit(EXIT_FAILURE);
		if (r < 0) {
		    if (errno == EINTR) continue;
		    fatalSys("read");
		}
		fprintf(stderr, "%c", c);
	    }
	    exit(EXIT_FAILURE);
	}
	setsid();
	signal(SIGHUP, SIG_IGN);
	i = fork();
	if (i < 0) {
	    fatalSys("fork");
	} else if (i != 0) {
	    exit(EXIT_SUCCESS);
	}

	if (chdir("/") < 0) {
	    fatalSys("chdir");
	}
	
	if (KidPipe[0] >= 0) {
	    close(KidPipe[0]);
	    KidPipe[0] = -1;
	}

	/* Point stdin/stdout/stderr to /dev/null */
	for (i=0; i<3; i++) {
	    close(i);
	}
	i = open("/dev/null", O_RDWR);
	if (i >= 0) {
	    dup2(i, 0);
	    dup2(i, 1);
	    dup2(i, 2);
	    if (i > 2) close(i);
	}
    }

    if (pidfile) {
	FILE *foo = NULL;
	if (KidPipe[1] >= 0) foo = fdopen(KidPipe[1], "w");
	struct flock fl;
	char buf[64];
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	LockFD = open(pidfile, O_RDWR|O_CREAT, 0666);
	if (LockFD < 0) {
	    syslog(LOG_INFO, "Could not open PID file %s: %s", pidfile, strerror(errno));
	    if (foo) fprintf(foo, "ECould not open PID file %s: %s\n", pidfile, strerror(errno));
	    exit(EXIT_FAILURE);
	}
	if (fcntl(LockFD, F_SETLK, &fl) < 0) {
	    syslog(LOG_INFO, "Could not lock PID file %s: Is another process running?", pidfile);
	    if (foo) fprintf(foo, "ECould not lock PID file %s: Is another process running?\n", pidfile);
	    exit(EXIT_FAILURE);
	}
	if (ftruncate(LockFD, 0) < 0) {
	    syslog(LOG_INFO, "Could not truncate PID file %s: %s", pidfile, strerror(errno));
	    if (foo) fprintf(foo, "ECould not truncate PID file %s: %s", pidfile, strerror(errno));
	    exit(EXIT_FAILURE);
        }
	snprintf(buf, sizeof(buf), "%lu\n", (unsigned long) getpid());
	if (write(LockFD, buf, strlen(buf)) < strlen(buf)) {
	    syslog(LOG_INFO, "Could not write PID file %s: %s", pidfile, strerror(errno));
	    if (foo) fprintf(foo, "ECould not write PID file %s: %s", pidfile, strerror(errno));
	    exit(EXIT_FAILURE);
	}

	/* Do not close fd... use it to retain lock */
    }

    /* Set signal handlers for SIGTERM and SIGINT */
    if (Event_HandleSignal(event_selector, SIGTERM, termHandler) < 0 ||
	Event_HandleSignal(event_selector, SIGINT, termHandler) < 0) {
	fatalSys("Event_HandleSignal");
    }

    /* Tell parent all is cool */
    if (KidPipe[1] >= 0) {
#pragma GCC diagnostic ignored "-Wunused-result"      
	write(KidPipe[1], "X", 1);
	close(KidPipe[1]);
#pragma GCC diagnostic warning "-Wunused-result"      
	KidPipe[1] = -1;
    }

    for(;;) {
	i = Event_HandleEvent(event_selector);
	if (i < 0) {
	    fatalSys("Event_HandleEvent");
	}

	if (draining == DRAIN_QUIT && NumActiveSessions == 0) {
	    syslog(LOG_INFO, "All active sessions are terminated and draining is set to quit.");
	    pppoe_terminate();
	}
    }
    return 0;
}

void
serverProcessPacket(Interface *i)
{
    int len;
    PPPoEPacket packet;
    int sock = i->sock;

    if (receivePacket(sock, &packet, &len) < 0) {
	return;
    }

    if (len < HDR_SIZE) {
	/* Impossible - ignore */
	return;
    }

    /* Sanity check on packet */
    if (PPPOE_VER(packet.vertype) != 1 || PPPOE_TYPE(packet.vertype) != 1) {
	/* Syslog an error */
	return;
    }

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus PPPoE length field (%u)",
	       (unsigned int) ntohs(packet.length));
	return;
    }

    switch(packet.code) {
    case CODE_PADI:
	processPADI(i, &packet, len);
	break;
    case CODE_PADR:
	processPADR(i, &packet, len);
	break;
    case CODE_PADT:
	/* Kill the child */
	processPADT(i, &packet, len);
	break;
    case CODE_SESS:
	/* Ignore SESS -- children will handle them */
	break;
    case CODE_PADO:
    case CODE_PADS:
	/* Ignore PADO and PADS totally */
	break;
    default:
	/* Syslog an error */
	break;
    }
}

/**********************************************************************
*%FUNCTION: sendErrorPADS
*%ARGUMENTS:
* sock -- socket to write to
* source -- source Ethernet address
* dest -- destination Ethernet address
* errorTag -- error tag
* errorMsg -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADS packet with an error message
***********************************************************************/
void
sendErrorPADS(int sock,
	      unsigned char *source,
	      unsigned char *dest,
	      int errorTag,
	      char *errorMsg)
{
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    uint16_t plen;
    PPPoETag err;
    int elen = strlen(errorMsg);

    memcpy(pads.ethHdr.h_dest, dest, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, source, ETH_ALEN);
    pads.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pads.vertype = PPPOE_VER_TYPE(1, 1);
    pads.code = CODE_PADS;

    pads.session = htons(0);
    plen = 0;

    err.type = htons(errorTag);
    err.length = htons(elen);

    memcpy(err.payload, errorMsg, elen);
    memcpy(cursor, &err, TAG_HDR_SIZE+elen);
    cursor += TAG_HDR_SIZE + elen;
    plen += TAG_HDR_SIZE + elen;

    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pads.length = htons(plen);
    sendPacket(NULL, sock, &pads, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: makePPPDIpArg
*%ARGUMENTS:
* buffer -- target buffer output, should be large enough (32 bytes worst case).
* localip -- the local IP address (myip), 0.0.0.0 for delegation.
* remoteip -- the local IP address (myip), 0.0.0.0 for delegation.
*%DESCRIPTION:
* prints the localip:remoteip argument for pppd, taking delegation
* into account, returning 0 if, and only if, both IP addresses are delegated,
* and 1 otherwise.
***********************************************************************/
static void
makePPPDIpArg(char* buffer, const unsigned char localip[IPV4ALEN], const unsigned char remoteip[IPV4ALEN])
{
    if (!ipIsNull(localip))
	buffer += sprintf(buffer, "%u.%u.%u.%u", localip[0], localip[1], localip[2], localip[3]);
    strcpy(buffer++, ":");
    if (!ipIsNull(remoteip))
	buffer += sprintf(buffer, "%u.%u.%u.%u", remoteip[0], remoteip[1], remoteip[2], remoteip[3]);
}

/**********************************************************************
*%FUNCTION: startPPPD
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Starts PPPD for user- or kernel-mode PPPoE
***********************************************************************/
static void
startPPPD(ClientSession *session)
{
    /* Leave some room */
    char *argv[64];

    char buffer[2 * SMALLBUF];

    char *mrumtu;
    int c = 0;

    syslog(LOG_INFO,
	   "Session %u created for client %02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) on %s using Service-Name '%s'",
	   (unsigned int) ntohs(session->sess),
	   session->eth[0], session->eth[1], session->eth[2],
	   session->eth[3], session->eth[4], session->eth[5],
	   (int) session->peerip[0], (int) session->peerip[1],
	   (int) session->peerip[2], (int) session->peerip[3],
	   session->ethif->name,
	   session->serviceName);

    argv[c++] = "pppd";

    if (UseLinuxKernelModePPPoE) {
	/* kernel mode */
	argv[c++] = "plugin";
	argv[c++] = plugin_path;

	/* Add "nic-" to interface name */
	snprintf(buffer, SMALLBUF, "nic-%s", session->ethif->name);
	argv[c++] = strdup(buffer);
	if (!argv[c-1]) {
	    exit(EXIT_FAILURE);
	}

	snprintf(buffer, SMALLBUF, "%u:%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned int) ntohs(session->sess),
		session->eth[0], session->eth[1], session->eth[2],
		session->eth[3], session->eth[4], session->eth[5]);
	argv[c++] = "rp_pppoe_sess";
	argv[c++] = strdup(buffer);
	if (!argv[c-1]) {
	    /* TODO: Send a PADT */
	    exit(EXIT_FAILURE);
	}
	argv[c++] = "rp_pppoe_service";
	argv[c++] = (char *) session->serviceName;
    } else {
	/* user mode */
	argv[c++] = "pty";

	/* Let's hope service-name does not have ' in it... */
	snprintf(buffer, sizeof(buffer), "%s -n -I %s -e %u:%02x:%02x:%02x:%02x:%02x:%02x%s -S '%s'",
		pppoe_path, session->ethif->name,
		(unsigned int) ntohs(session->sess),
		session->eth[0], session->eth[1], session->eth[2],
		session->eth[3], session->eth[4], session->eth[5],
		PppoeOptions, session->serviceName);
	argv[c++] = strdup(buffer);
	if (!argv[c-1]) {
	    /* TODO: Send a PADT */
	    exit(EXIT_FAILURE);
	}

	if (Synchronous) {
	    argv[c++] = "sync";
	}
    }

    argv[c++] = "file";
    argv[c++] = pppoptfile;

    makePPPDIpArg(buffer, session->myip, session->peerip);
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }

    argv[c++] = "nodetach";
    argv[c++] = "noaccomp";
    argv[c++] = "nopcomp";
    argv[c++] = "default-asyncmap";

    argv[c++] = "remotenumber";
    snprintf(buffer, SMALLBUF, "%02x:%02x:%02x:%02x:%02x:%02x",
	    session->eth[0], session->eth[1], session->eth[2],
	    session->eth[3], session->eth[4], session->eth[5]);
    if (!(argv[c++] = strdup(buffer))) {
	exit(EXIT_FAILURE);
    }

    if (PassUnitOptionToPPPD) {
	argv[c++] = "unit";
	sprintf(buffer, "%u", (unsigned int) (ntohs(session->sess) - 1 - SessOffset));
	if (!(argv[c++] = strdup(buffer))) {
            exit(EXIT_FAILURE);
        }
    }
    if (session->requested_mtu > 1492) {
	sprintf(buffer, "%u", (unsigned int) session->requested_mtu);
        if (!(mrumtu = strdup(buffer))) {
            exit(EXIT_FAILURE);
        }
	argv[c++] = "mru";
        argv[c++] = mrumtu;
	argv[c++] = "mtu";
        argv[c++] = mrumtu;
    } else {
	argv[c++] = "mru";
	argv[c++] = "1492";
	argv[c++] = "mtu";
	argv[c++] = "1492";
    }
    argv[c++] = NULL;
    execv(pppd_path, argv);
    exit(EXIT_FAILURE);
}

/**********************************************************************
* %FUNCTION: InterfaceHandler
* %ARGUMENTS:
*  es -- event selector (ignored)
*  fd -- file descriptor which is readable
*  flags -- ignored
*  data -- Pointer to the Interface structure
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a packet ready at an interface
***********************************************************************/
void
InterfaceHandler(EventSelector *es,
		 int fd,
		 unsigned int flags,
		 void *data)
{
    serverProcessPacket((Interface *) data);
}

/**********************************************************************
* %FUNCTION: PppoeStopSession
* %ARGUMENTS:
*  ses -- the session
*  reason -- reason session is being stopped.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Kills pppd.
***********************************************************************/
static void
PppoeStopSession(ClientSession *ses,
		 char const *reason)
{
    /* Temporary structure for sending PADT's. */
    PPPoEConnection conn;

    memset(&conn, 0, sizeof(conn));
    conn.hostUniq = NULL;

    memcpy(conn.myEth, ses->ethif->mac, ETH_ALEN);
    conn.discoverySocket = ses->ethif->sock;
    conn.session = ses->sess;
    memcpy(conn.peerEth, ses->eth, ETH_ALEN);
    sendPADT(&conn, reason);
    ses->flags |= FLAG_SENT_PADT;

    if (ses->pid) {
	kill(ses->pid, SIGTERM);
    }
    ses->funcs = &DefaultSessionFunctionTable;
}

/**********************************************************************
* %FUNCTION: PppoeSessionIsActive
* %ARGUMENTS:
*  ses -- the session
* %RETURNS:
*  True if session is active, false if not.
***********************************************************************/
static int
PppoeSessionIsActive(ClientSession *ses)
{
    return (ses->pid != 0);
}

/**********************************************************************
* %FUNCTION: pppoe_alloc_session
* %ARGUMENTS:
*  None
* %RETURNS:
*  NULL if no session is available, otherwise a ClientSession structure.
* %DESCRIPTION:
*  Allocates a ClientSession structure and removes from free list, puts
*  on busy list
***********************************************************************/
ClientSession *
pppoe_alloc_session(void)
{
    ClientSession *ses = FreeSessions;
    if (!ses) return NULL;

    /* Remove from free sessions list */
    if (ses == LastFreeSession) {
	LastFreeSession = NULL;
    }
    FreeSessions = ses->next;

    /* Put on busy sessions list */
    ses->next = BusySessions;
    BusySessions = ses;

    /* Initialize fields to sane values */
    ses->funcs = &DefaultSessionFunctionTable;
    ses->pid = 0;
    ses->ethif = NULL;
    memset(ses->eth, 0, ETH_ALEN);
    ses->flags = 0;
    ses->startTime = time(NULL);
    ses->serviceName = "";
    ses->requested_mtu = 0;
    NumActiveSessions++;
    return ses;
}

/**********************************************************************
* %FUNCTION: pppoe_free_session
* %ARGUMENTS:
*  ses -- session to free
* %RETURNS:
*  0 if OK, -1 if error
* %DESCRIPTION:
*  Places a ClientSession on the free list.
***********************************************************************/
int
pppoe_free_session(ClientSession *ses)
{
    ClientSession *cur, *prev;

    cur = BusySessions;
    prev = NULL;
    while (cur) {
	if (ses == cur) break;
	prev = cur;
	cur = cur->next;
    }

    if (!cur) {
	syslog(LOG_ERR, "pppoe_free_session: Could not find session %p on busy list", (void *) ses);
	return -1;
    }

    /* Remove from busy sessions list */
    if (prev) {
	prev->next = ses->next;
    } else {
	BusySessions = ses->next;
    }

    /* Add to end of free sessions */
    ses->next = NULL;
    if (LastFreeSession) {
	LastFreeSession->next = ses;
	LastFreeSession = ses;
    } else {
	FreeSessions = ses;
	LastFreeSession = ses;
    }

    /* Initialize fields to sane values */
    ses->funcs = &DefaultSessionFunctionTable;
    ses->pid = 0;
    memset(ses->eth, 0, ETH_ALEN);
    ses->flags = 0;
    NumActiveSessions--;
    return 0;
}

/**********************************************************************
* %FUNCTION: sendHURLorMOTM
* %ARGUMENTS:
*  conn -- PPPoE connection
*  url -- a URL, which *MUST* begin with "http://" or it won't be sent, or
*         a message.
*  tag -- one of TAG_HURL or TAG_MOTM
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends a PADM packet contaning a HURL or MOTM tag to the victim...er, peer.
***********************************************************************/
void
sendHURLorMOTM(PPPoEConnection *conn, char const *url, uint16_t tag)
{
    PPPoEPacket packet;
    PPPoETag hurl;
    size_t elen;
    unsigned char *cursor = packet.payload;
    uint16_t plen = 0;

    if (!conn->session) return;
    if (conn->discoverySocket < 0) return;

    if (tag == TAG_HURL) {
	if (strncmp(url, "http://", 7) && strncmp(url, "https://", 8)) {
	    syslog(LOG_WARNING, "sendHURL(%s): URL must begin with http:// or https://", url);
	    return;
	}
    } else {
	tag = TAG_MOTM;
    }

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.vertype = PPPOE_VER_TYPE(1, 1);
    packet.code = CODE_PADM;
    packet.session = conn->session;

    elen = strlen(url);
    if (elen > 256) {
	syslog(LOG_WARNING, "MOTM or HURL too long: %d", (int) elen);
	return;
    }

    hurl.type = htons(tag);
    hurl.length = htons(elen);
    strcpy((char *) hurl.payload, url);
    memcpy(cursor, &hurl, elen + TAG_HDR_SIZE);
    cursor += elen + TAG_HDR_SIZE;
    plen += elen + TAG_HDR_SIZE;

    packet.length = htons(plen);

    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
#ifdef DEBUGGING_ENABLED
    if (conn->debugFile) {
	dumpPacket(conn->debugFile, &packet, "SENT");
	fprintf(conn->debugFile, "\n");
	fflush(conn->debugFile);
    }
#endif
}

/**********************************************************************
* %FUNCTION: handle_status
***********************************************************************/
#define opt_matches(o)		(wlen == 0 || strncmp(opt, o, wlen) == 0)
#define opt_outp(o, fmt, ...)	cs_ret_printf(client, "%20s: " fmt "\n", o, ## __VA_ARGS__)
#define opt_status(o, fmt, ...)	do { if (opt_matches(o)) { opt_outp(o, fmt, ## __VA_ARGS__); }} while(0)

static int handle_status(ClientConnection *client, const char* const* argv, int argi, void* pvt, void* clientpvt)
{
    char opt[64]; /* WARNING: may not be null terminated!!!! */
    size_t wlen = 0;
    while (wlen < sizeof(opt) && argv[argi]) {
	int r = snprintf(&opt[wlen], sizeof(opt) - wlen, "%s ", argv[argi++]);
	if (r < 0) {
	    syslog(LOG_WARNING, "snprintf error: %s", strerror(errno));
	    return -1;
	}
	wlen += r;
    }
    if (wlen > sizeof(opt))
	wlen = sizeof(opt);
    if (opt[wlen-1] == ' ')
	--wlen;

    opt_status("active sessions", "%zu", NumActiveSessions);
    opt_status("maximum sessions", "%zu", NumSessionSlots);
    opt_status("sessions per mac", "%d", MaxSessionsPerMac);
    opt_status("interface count", "%d", NumInterfaces);
    opt_status("global drain", "%s", drain_string[draining]);
    if (opt_matches("interface list")) {
        int i;
	for (i = 0; i < NumInterfaces; ++i) {
	    if (!opt_matches(interfaces[i].name))
		continue;
	    cs_ret_printf(client, "Interface details: %s\n", interfaces[i].name);
	    opt_outp("local mac", "%02x:%02x:%02x:%02x:%02x:%02x",
		    interfaces[i].mac[0], interfaces[i].mac[1], interfaces[i].mac[2],
		    interfaces[i].mac[3], interfaces[i].mac[4], interfaces[i].mac[5]);
	    opt_outp("mtu", "%u", interfaces[i].mtu);
	}
    }
    cs_ret_printf(client, "-- end --\n");
    return 0;
}
#undef opt_status
#undef opt_outp
#undef opt_matches

/**********************************************************************
* %FUNCTION: handle_set_drain
***********************************************************************/
static int handle_set_drain(ClientConnection *client, const char* const* argv, int argi, void* pvt, void* clientpvt)
{
    if (!argv[argi]) {
	cs_ret_printf(client, "USAGE: set drain {off|on|quit}\n");
	return 0;
    }

    if (strcmp(argv[argi], "off") == 0) {
	draining = DRAIN_OFF;
	cs_ret_printf(client, "Server is not draining\n");
    } else if (strcmp(argv[argi], "on") == 0) {
	draining = DRAIN_ON;
	cs_ret_printf(client, "Server is now draining\n");
    } else if (strcmp(argv[argi], "quit") == 0) {
	draining = DRAIN_QUIT;
	cs_ret_printf(client, "Server is now draining, and will quit when all clients are disconnected\n");
    } else {
	cs_ret_printf(client, "Invalid value %s for set drain, value must be one of off, on or quit.\n", argv[argi]);
    }
    return 0;
}
