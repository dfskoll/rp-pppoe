/***********************************************************************
*
* pppoe-bridge.c
*
* Implementation of a user-space PPPoE-to-PPP bridge
*
* Copyright (C) 2014 by Savoir Faire Linux.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* $Id$
*
* LIC: GPL
*
* This file is derived from pppoe.c by Patrick Keroulas
* (patrick.keroulas@savoirfairelinux.com).
*
***********************************************************************/

#include "config.h"
#include "types.h"

#if defined(HAVE_NETPACKET_PACKET_H) || defined(HAVE_LINUX_IF_PACKET_H)
#define _POSIX_SOURCE 1 /* For sigaction defines */
#endif

#include "pppoe-bridge.h"
#include "modem.h"
#include "md5.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/file.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <time.h>

#include <signal.h>

#ifdef HAVE_LICENSE
#include "license.h"
#include "licensed-only/servfuncs.h"
static struct License const *ServerLicense;
static struct License const *ClusterLicense;
#else
#define control_session_started(x) (void) 0
#define control_session_terminated(x) (void) 0
#define control_exit() (void) 0
#endif

#ifdef HAVE_L2TP
extern PppoeSessionFunctionTable L2TPSessionFunctionTable;
extern void pppoe_to_l2tp_add_interface(EventSelector *es,
					Interface *interface);
#endif

static void InterfaceHandler(EventSelector *es, int fd,
        unsigned int flags, void *data);
static void ModemHandler(EventSelector *es, int fd,
        unsigned int flags, void *data);
static void sendErrorPADS(int sock, unsigned char *source, unsigned char *dest,
        int errorTag, char *errorMsg);
void sysErr(char const *str);
void fatalSys(char const *str);
void rp_fatal(char const *str);


#define CHECK_ROOM(cursor, start, len) \
do {\
    if (((cursor)-(start))+(len) > MAX_PPPOE_PAYLOAD) { \
	syslog(LOG_ERR, "Would create too-long packet"); \
	return; \
    } \
} while(0)

static ClientSession* PppoeGetSession(int sessionID);
static void PppoeStartSession(ClientSession *ses);
static void PppoeStopSession(ClientSession *ses, char const *reason);
static int PppoeSessionIsActive(ClientSession *ses);

/* Service-Names we advertise */
#define MAX_SERVICE_NAMES 64
static int NumServiceNames = 0;
static char const *ServiceNames[MAX_SERVICE_NAMES];

PppoeSessionFunctionTable DefaultSessionFunctionTable = {
    PppoeStartSession,
    PppoeStopSession,
    PppoeSessionIsActive,
    NULL
};

/* An array of client sessions */
ClientSession *Sessions = NULL;
ClientSession *FreeSessions = NULL;
ClientSession *LastFreeSession = NULL;
ClientSession *BusySessions = NULL;
ClientSession *CurrentSession = NULL;

/* Interfaces we're listening on */
Interface interfaces[MAX_INTERFACES];
int NumInterfaces = 0;

/* The number of session slots */
size_t NumSessionSlots;

/* Maximum number of sessions per MAC address */
int MaxSessionsPerMac;

/* Number of active sessions */
size_t NumActiveSessions = 0;

/* Event Selector */
EventSelector *event_selector;

/* Requested max_ppp_payload */
static UINT16_t max_ppp_payload = 0;

static int Debug = 0;

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
#define HOSTNAMELEN 256

/* Default interface if no -I option given */
#define DEFAULT_IF "eth0"

/* Default modem tty if no -t option given */
#define DEFAULT_TTY "/dev/ttyS0"

/* Access concentrator name */
char *ACName = NULL;

/* Do we randomize session numbers? */
int RandomizeSessionNumbers = 0;

static PPPoETag hostUniq;
static PPPoETag relayId;
static PPPoETag receivedCookie;
static PPPoETag requestedService;

/* Session variables */
unsigned char ethInputBuf[READ_CHUNK];
struct timeval eth_timeout;
struct timeval modem_timeout;

/* Clamp MSS to this value */
int clampMss = 0;


char *provider_num = NULL;
char *modem_port=NULL;

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
parsePADITags(UINT16_t type, UINT16_t len, unsigned char *data,
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
parsePADRTags(UINT16_t type, UINT16_t len, unsigned char *data,
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
    UINT16_t plen;

    int sock = ethif->discovery_sock;
    int i;
    int ok = 0;
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	syslog(LOG_ERR, "PADI packet from non-unicast source address");
	return;
    }

    /* Ignore PADI's which aren't broadcast */
    if (NOT_BROADCAST(packet->ethHdr.h_dest)) {
	syslog(LOG_ERR, "PADI packet to non-broadcast source address");
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
    /* Session ID must be 0 */
    if (packet->session != 0) {
	syslog(LOG_INFO, "PADI ignored - Session non null");
	return;
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

    if(modem_is_busy){
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Bridge: busy.");
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
    pado.ver = 1;
    pado.type = 1;
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
	    UINT16_t mru = htons(max_ppp_payload);
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
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADT's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    ClientSession *session = PppoeGetSession(packet->session);
    if (!session)
    {
        syslog(LOG_ERR, "PADT for session %u but couldn't retrieve it.",
                packet->session);
        return;
    }

    /* If source MAC does not match, do not kill session */
    if (memcmp(packet->ethHdr.h_source, session->eth, ETH_ALEN)) {
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
	       session->eth[0],
	       session->eth[1],
	       session->eth[2],
	       session->eth[3],
	       session->eth[4],
	       session->eth[5]);
	return;
    }
    session->flags |= FLAG_RECVD_PADT;
    parsePacket(packet, parseLogErrs, NULL);
    session->funcs->stop(session, "Received PADT");
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
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    UINT16_t plen;
    int i;
    int sock = ethif->discovery_sock;
    unsigned char *myAddr = ethif->mac;
    int slen = 0;
    char const *serviceName = NULL;

#ifdef HAVE_LICENSE
    int freemem;
#endif

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
    /* Session ID must be 0 */
    if (packet->session != 0) {
	syslog(LOG_INFO, "PADI ignored - Session non null");
	return;
    }

    max_ppp_payload = 0;
    if (parsePacket(packet, parsePADRTags, NULL)) {
	/* Drop it -- do not send error PADS */
	return;
    }

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
	syslog(LOG_ERR, "PADR packet with no SERVICE_NAME tag");
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Bridge: No service name tag");
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
	    syslog(LOG_ERR, "PADR packet asking for unsupported service %.*s", (int) ntohs(requestedService.length), requestedService.payload);
	    sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
			  TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Bridge: Invalid service name tag");
	    return;
	}
    } else {
	serviceName = "";
    }


#ifdef HAVE_LICENSE
    /* Are we licensed for this many sessions? */
    if (License_NumLicenses("PPPOE-SESSIONS") <= NumActiveSessions) {
	syslog(LOG_ERR, "Insufficient session licenses (%02x:%02x:%02x:%02x:%02x:%02x)",
	       (unsigned int) packet->ethHdr.h_source[0],
	       (unsigned int) packet->ethHdr.h_source[1],
	       (unsigned int) packet->ethHdr.h_source[2],
	       (unsigned int) packet->ethHdr.h_source[3],
	       (unsigned int) packet->ethHdr.h_source[4],
	       (unsigned int) packet->ethHdr.h_source[5]);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Bridge: No session licenses available");
	return;
    }
#endif
    /* Enough free memory? */
#ifdef HAVE_LICENSE
    freemem = getFreeMem();
    if (freemem < MIN_FREE_MEMORY) {
	syslog(LOG_WARNING,
	       "Insufficient free memory to create session: Want %d, have %d",
	       MIN_FREE_MEMORY, freemem);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Insufficient free RAM");
	return;
    }
#endif
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
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Bridge: No client slots available");
	return;
    }

    if(modem_is_busy){
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Bridge: busy.");
        return;
    }

    /* Set up client session peer Ethernet address */
    memcpy(cliSession->eth, packet->ethHdr.h_source, ETH_ALEN);
    cliSession->ethif = ethif;
    cliSession->flags = 0;
    cliSession->funcs = &DefaultSessionFunctionTable;
    cliSession->startTime = time(NULL);
    cliSession->serviceName = serviceName;
    while ((cliSession->sess == 0) || (cliSession->sess == 0xFFFF))
    {
        cliSession->sess = rand();
    }

    /* ------------------ Modem --------------------------------
     * check that both the modem and ISP service are available.*/
    if(!modemOpen())
    {
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Bridge: Modem not available.");
	pppoe_free_session(cliSession);
        return;
    }

    if(modemSignalStrength() < 2)
    {
        syslog(LOG_ERR, "Modem: signal=too weak");
        modemClose();
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Bridge: Weak signal.");
	pppoe_free_session(cliSession);
        return;
    }

    if (!modemDial(provider_num))
    {
        modemHangup();
        modemClose();
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Bridge: Couldn't dialup.");
	pppoe_free_session(cliSession);
        return;
    }

    /* --------- Send PADS packet back ---------------*/
    memcpy(pads.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, myAddr, ETH_ALEN);
    pads.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pads.ver = 1;
    pads.type = 1;
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
	    UINT16_t mru = htons(max_ppp_payload);
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

    cliSession->funcs->start(cliSession);
}

/**********************************************************************
*%FUNCTION: processPPPOE
*%ARGUMENTS:
* ethif -- interface
* packet -- PPPoE Session packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Extract payload and transmit to tty modem.
***********************************************************************/
void
processPPPOE( PPPoEPacket *packet, int len)
{
    int plen, mlen;
    int i;
    unsigned char *ptr = ethInputBuf;
    unsigned char c;
    UINT16_t fcs;
    unsigned char header[2] = {FRAME_ADDR, FRAME_CTRL};
    unsigned char tail[2];
#ifdef USE_BPF
    int type;
#endif

    ClientSession *session = PppoeGetSession(packet->session);
    if (!session)
    {
        syslog(LOG_ERR, "pppoe: couldn't retrieve session ID=%u.", packet->session);
        return;
    }
#ifdef DEBUGGING_ENABLED
    if(Debug)
        syslog(LOG_INFO, "Session %u: pppoe recieved packet", session->sess);
#endif

    PPPoEConnection *conn = &session->conn;
    if(!conn)
    {
        return;
    }

#ifdef DEBUGGING_ENABLED
    if (conn->debugFile) {
	dumpPacket(conn->debugFile, packet, "RCVD");
	fprintf(conn->debugFile, "\n");
	fflush(conn->debugFile);
    }
#endif

#ifdef USE_BPF
    /* Make sure this is a session packet before processing further */
    type = etherType(packet);
    if (type == Eth_PPPOE_Discovery) {
	sessionDiscoveryPacket(packet);
    } else if (type != Eth_PPPOE_Session) {
	return;
    }
#endif

    if (memcmp(packet->ethHdr.h_dest, conn->myEth, ETH_ALEN)) {
	return;
    }

    if (memcmp(packet->ethHdr.h_source, conn->peerEth, ETH_ALEN)) {
	/* Not for us -- must be another session.  This is not an error,
	   so don't log anything.  */
	return;
    }

    if ((packet->session != conn->session) || (packet->session == 0xFFFF)){
	/* Not for us -- must be another session.  This is not an error,
	   so don't log anything.  */
	return;
    }
    plen = ntohs(packet->length);
    if (plen + HDR_SIZE > len) {
	syslog(LOG_ERR, "pppoe: bogus length field in session packet %d (%d)",
	       (int) plen, (int) len);
	return;
    }

    /* reset timer */
    Event_ChangeTimeout(session->ethif->session_eh, eth_timeout);

    /* Clamp MSS */
    if (clampMss) {
	clampMSS(packet, "incoming", clampMss);
    }

    /* Compute FCS */
    fcs = pppFCS16(PPPINITFCS16, header, 2);
    fcs = pppFCS16(fcs, packet->payload, plen) ^ 0xffff;
    tail[0] = fcs & 0x00ff;
    tail[1] = (fcs >> 8) & 0x00ff;

    /* Build a buffer to send to PPP */
    *ptr++ = FRAME_FLAG;
    *ptr++ = FRAME_ADDR;
    *ptr++ = FRAME_ESC;
    *ptr++ = FRAME_CTRL ^ FRAME_ENC;

    for (i=0; i<plen; i++) {
	c = packet->payload[i];
	if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
	    *ptr++ = FRAME_ESC;
	    *ptr++ = c ^ FRAME_ENC;
	} else {
	    *ptr++ = c;
	}
    }
    for (i=0; i<2; i++) {
	c = tail[i];
	if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
	    *ptr++ = FRAME_ESC;
	    *ptr++ = c ^ FRAME_ENC;
	} else {
	    *ptr++ = c;
	}
    }
    *ptr++ = FRAME_FLAG;

#ifdef DEBUGGING_ENABLED
    if(Debug)
    {
        syslog(LOG_INFO, "pppoe: eth < [%d]", plen);
    }
#endif

    mlen = ptr - ethInputBuf;

    ethInputBuf[mlen]='\0';

    /* DFS: This seems wrong.  Surely you can't just drop packets, but
       have to make sure there's no guard time on either side of +++ that
       could confuse the modem? */
    if(strstr((char *)ethInputBuf, "+++"))
    {
        /* Discard packets that contains the modem's escape sequence */
        return;
    }

    /* Ship it out */
    if (!modemWriteBuf((char*) ethInputBuf, mlen)) {
	fatalSys("pppoe: Couldn't write to modem.");
    }
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
    syslog(LOG_INFO, "Terminating on signal %d -- killing all PPPoE sessions", sig);
    killAllSessions();
    control_exit();
    exit(0);
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
#ifdef USE_BPF
    fprintf(stderr, "   -I if_name     -- Specify interface (REQUIRED)\n");
#else
    fprintf(stderr, "   -I if_name     -- Specify interface (default %s.)\n", DEFAULT_IF);
#endif
    fprintf(stderr, "   -T timeout     -- Specify inactivity timeout in seconds.\n");
    fprintf(stderr, "   -C name        -- Set access concentrator name.\n");
    fprintf(stderr, "   -m MSS         -- Clamp incoming and outgoing MSS options.\n");
    fprintf(stderr, "   -S name        -- Advertise specified service-name.\n");
    fprintf(stderr, "   -N num         -- Set provider number to be dialed.\n");
    fprintf(stderr, "   -f disc:sess   -- Set Ethernet frame types (hex).\n");
    fprintf(stderr, "   -X pidfile     -- Write PID and lock pidfile.\n");
    fprintf(stderr, "   -r             -- Randomize session numbers.\n");
    fprintf(stderr, "   -d             -- Debug session creation.\n");
    fprintf(stderr, "   -x n           -- Limit to 'n' sessions/MAC address.\n");
#ifdef HAVE_LICENSE
    fprintf(stderr, "   -c secret:if:port -- Enable clustering on interface 'if'.\n");
    fprintf(stderr, "   -1             -- Allow only one session per user.\n");
#endif

    fprintf(stderr, "   -i             -- Ignore PADI if no free sessions.\n");
    fprintf(stderr, "   -t             -- Modem tty (default: %s).\n", DEFAULT_TTY);
    fprintf(stderr, "   -h             -- Print usage information.\n\n");
    fprintf(stderr, "PPPoE-Bridge Version %s, Copyright (C) 2001-2014 Roaring Penguin Software Inc.\nCopyright (C) 2014 Savoir-faire Linux.\n", RP_VERSION);

#ifndef HAVE_LICENSE
    fprintf(stderr, "PPPoE-Bridge comes with ABSOLUTELY NO WARRANTY.\n");
    fprintf(stderr, "This is free software, and you are welcome to redistribute it\n");
    fprintf(stderr, "under the terms of the GNU General Public License, version 2\n");
    fprintf(stderr, "or (at your option) any later version.\n");
#endif
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
    int beDaemon = 1;
    int found;
    int timeout = 0;
    unsigned int discoveryType, sessionType;
    char *pidfile = NULL;
    char c;

#ifdef HAVE_LICENSE
    int use_clustering = 0;
#endif

    char *options = "X:ix:hI:C:T:m:FN:f:rdc:S:1t:";

    if (getuid() != geteuid() ||
	getgid() != getegid()) {
	fprintf(stderr, "SECURITY WARNING: pppoe-server will NOT run suid or sgid.  Fix your installation.\n");
	exit(1);
    }

    memset(interfaces, 0, sizeof(interfaces));

    /* Initialize syslog */
    openlog("pppoe-bridge", LOG_PID, LOG_DAEMON);

    /* Default number of session slots */
    NumSessionSlots = DEFAULT_MAX_SESSIONS;
    MaxSessionsPerMac = 0; /* No limit */
    NumActiveSessions = 0;

    modem_timeout.tv_sec = eth_timeout.tv_sec = 0;

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

	case 'S':
	    if (NumServiceNames == MAX_SERVICE_NAMES) {
		fprintf(stderr, "Too many '-S' options (%d max)",
			MAX_SERVICE_NAMES);
		exit(1);
	    }
	    ServiceNames[NumServiceNames] = strdup(optarg);
	    if (!ServiceNames[NumServiceNames]) {
		fprintf(stderr, "Out of memory");
		exit(1);
	    }
	    NumServiceNames++;
	    break;

	case 'c':
#ifndef HAVE_LICENSE
	    fprintf(stderr, "Clustering capability not available.\n");
	    exit(1);
#else
	    cluster_handle_option(optarg);
	    use_clustering = 1;
	    break;
#endif

	case 'd':
	    Debug = 1;
	    break;

	case 'r':
	    RandomizeSessionNumbers = 1;
	    break;

	case 'X':
	    SET_STRING(pidfile, optarg);
	    break;

	case 'f':
	    if (sscanf(optarg, "%x:%x", &discoveryType, &sessionType) != 2) {
		fprintf(stderr, "Illegal argument to -f: Should be disc:sess in hex\n");
		exit(EXIT_FAILURE);
	    }
	    Eth_PPPOE_Discovery = (UINT16_t) discoveryType;
	    Eth_PPPOE_Session   = (UINT16_t) sessionType;
	    break;

	case 'F':
	    beDaemon = 0;
	    break;

	case 'I':
	    if (NumInterfaces >= MAX_INTERFACES) {
		fprintf(stderr, "Too many -I options (max %d)\n",
			MAX_INTERFACES);
		exit(EXIT_FAILURE);
	    }
	    found = 0;
	    for (i=0; i<NumInterfaces; i++) {
		if (!strncmp(interfaces[i].name, optarg, IFNAMSIZ)) {
		    found = 1;
		    break;
		}
	    }
	    if (!found) {
		strncpy(interfaces[NumInterfaces].name, optarg, IFNAMSIZ);
		NumInterfaces++;
	    }
	    break;

	case 'C':
	    SET_STRING(ACName, optarg);
	    break;

	case 'T':
	    if (sscanf(optarg, "%d", &timeout) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
            modem_timeout.tv_sec = eth_timeout.tv_sec = timeout;
            modem_timeout.tv_usec = eth_timeout.tv_usec = 0;
            break;

	case 'm':
	    clampMss = (int) strtol(optarg, NULL, 10);
	    if (clampMss < 536) {
		fprintf(stderr, "-m: %d is too low (min 536)\n", clampMss);
		exit(EXIT_FAILURE);
	    }
	    if (clampMss > 1452) {
		fprintf(stderr, "-m: %d is too high (max 1452)\n", clampMss);
		exit(EXIT_FAILURE);
	    }
	    break;

        case 't':
	    SET_STRING(modem_port, optarg);
	    break;

        case 'N':
	    SET_STRING(provider_num, optarg);
	    break;

	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);

	case '1':
#ifdef HAVE_LICENSE
	    MaxSessionsPerUser = 1;
#else
	    fprintf(stderr, "-1 option not valid.\n");
	    exit(1);
#endif
	    break;
	}
    }

#ifdef HAVE_LICENSE
    License_SetVersion(SERVPOET_VERSION);
    License_ReadBundleFile("/etc/rp/bundle.txt");
    License_ReadFile("/etc/rp/license.txt");
    ServerLicense = License_GetFeature("PPPOE-SERVER");
    if (!ServerLicense) {
	fprintf(stderr, "License: GetFeature failed: %s\n",
		License_ErrorMessage());
	exit(1);
    }
#endif

#ifdef USE_LINUX_PACKET
#ifndef HAVE_STRUCT_SOCKADDR_LL
    fprintf(stderr, "The PPPoE server does not work on Linux 2.0 kernels.\n");
    exit(EXIT_FAILURE);
#endif
#endif

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

    if (!modem_port) {
	modem_port = strDup(DEFAULT_TTY);
    }

    if (!provider_num) {
        provider_num = strDup("000000000");
    }

    /* Allocate memory for sessions */
    Sessions = calloc(NumSessionSlots, sizeof(ClientSession));
    if (!Sessions) {
	rp_fatal("Cannot allocate memory for session slots");
    }

    /* Initialize our random cookie.  Try /dev/urandom; if that fails,
       use PID and rand() */
    fp = fopen("/dev/urandom", "r");
    if (fp) {
	unsigned int x;
	fread(&x, 1, sizeof(x), fp);
	srand(x);
	fread(&CookieSeed, 1, SEED_LEN, fp);
	fclose(fp);
    } else {
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

    /* Open all the interfaces */
    for (i=0; i<NumInterfaces; i++) {
	interfaces[i].mtu = 0;
	interfaces[i].discovery_sock = openInterface(interfaces[i].name, Eth_PPPOE_Discovery, interfaces[i].mac, &interfaces[i].mtu);
    }

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    /* Create event selector */
    event_selector = Event_CreateSelector();
    if (!event_selector) {
	rp_fatal("Could not create EventSelector -- probably out of memory");
    }

    /* Control channel */
#ifdef HAVE_LICENSE
    if (control_init(argc, argv, event_selector)) {
	rp_fatal("control_init failed");
    }
#endif

    if(Debug)
    {
        /* event debug seems to corrupt data, shoud be used only for dev purpose */
        /*
        if(!Event_EnableDebugging("/tmp/event"))
        {
            fprintf(stderr, "couldn't create event debug file");
        }
        */
        modemDebugEnable(TRUE);
    }
    sleep(1);

    /* Create event handler for each interface */
    for (i = 0; i<NumInterfaces; i++) {
	interfaces[i].discovery_eh = Event_AddHandler(event_selector,
					    interfaces[i].discovery_sock,
					    EVENT_FLAG_READABLE,
					    InterfaceHandler,
					    &interfaces[i]);
#ifdef HAVE_L2TP
	interfaces[i].session_sock = -1;
#endif
	if (!interfaces[i].discovery_eh) {
	    rp_fatal("Event_AddHandler failed");
	}
    }

#ifdef HAVE_LICENSE
    if (use_clustering) {
	ClusterLicense = License_GetFeature("PPPOE-CLUSTER");
	if (!ClusterLicense) {
	    fprintf(stderr, "License: GetFeature failed: %s\n",
		    License_ErrorMessage());
	    exit(1);
	}
	if (!License_Expired(ClusterLicense)) {
	    if (cluster_init(event_selector) < 0) {
		rp_fatal("cluster_init failed");
	    }
	}
    }
#endif

#ifdef HAVE_L2TP
    for (i=0; i<NumInterfaces; i++) {
	pppoe_to_l2tp_add_interface(event_selector,
				    &interfaces[i]);
    }
#endif

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

	chdir("/");

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
	    exit(1);
	}
	if (fcntl(LockFD, F_SETLK, &fl) < 0) {
	    syslog(LOG_INFO, "Could not lock PID file %s: Is another process running?", pidfile);
	    if (foo) fprintf(foo, "ECould not lock PID file %s: Is another process running?\n", pidfile);
	    exit(1);
	}
	ftruncate(LockFD, 0);
	snprintf(buf, sizeof(buf), "%lu\n", (unsigned long) getpid());
	write(LockFD, buf, strlen(buf));
	/* Do not close fd... use it to retain lock */
    }

    /* Set signal handlers for SIGTERM and SIGINT */
    if (Event_HandleSignal(event_selector, SIGTERM, termHandler) < 0 ||
	Event_HandleSignal(event_selector, SIGINT, termHandler) < 0) {
	fatalSys("Event_HandleSignal");
    }

    /* Tell parent all is cool */
    if (KidPipe[1] >= 0) {
	write(KidPipe[1], "X", 1);
	close(KidPipe[1]);
	KidPipe[1] = -1;
    }

    // set modem config
    if(!modemInit(modem_port, 115200))
  	exit(EXIT_FAILURE);

    for(;;) {
	i = Event_HandleEvent(event_selector);
	if (i < 0) {
	    fatalSys("Event_HandleEvent");
	}
        else if(i == 0)
	    syslog(LOG_INFO, "Event handler: got a timeout");

#ifdef HAVE_LICENSE
	if (License_Expired(ServerLicense)) {
	    syslog(LOG_INFO, "Server license has expired -- killing all PPPoE sessions");
	    killAllSessions();
	    control_exit();
	    exit(0);
	}
#endif
    }
    return 0;
}


/**********************************************************************
*%FUNCTION: processEth
*%ARGUMENTS:
* sock -- socket to read from
* i -- Ethernet interface
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Read packet from eth interface, detect packet type and call the handler.
***********************************************************************/
void
processEth(int sock, Interface *i)
{
    int len;
    PPPoEPacket packet;

    if (receivePacket(sock, &packet, &len) < 0) {
	return;
    }

    if (len < HDR_SIZE) {
	/* Impossible - ignore */
	return;
    }

    /* Sanity check on packet */
    if (packet.ver != 1 || packet.type != 1) {
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
	syslog(LOG_INFO, "Discovery: recieved PADI");
	processPADI(i, &packet, len);
	break;
    case CODE_PADR:
	syslog(LOG_INFO, "Discovery: recieved PADR");
        processPADR(i, &packet, len);
	break;
    case CODE_PADT:
	processPADT(i, &packet, len);
	break;
    case CODE_SESS:
        processPPPOE(&packet, len);
	break;
    case CODE_PADO:
    case CODE_PADS:
	/* Ignore PADO and PADS totally */
	break;
    default:
	/* Syslog an error */
	syslog(LOG_ERR, "Recieved UNEXPECTED packet");
	break;
    }
}

void processModem(int fd, ClientSession *session)
{
    int r = modemReadBuf((char *)modem_input_buffer, READ_CHUNK);

    if (r < 0) {
	fatalSys("Modem: error while reading");
    }

    if (r == 0) {
        PppoeStopSession(session, "Modem: EOF (may be caused by a timeout)");
        return;
    }
#ifdef DEBUGGING_ENABLED
    if(Debug)
        syslog(LOG_INFO, "Session %u: modem recieved packet", session->sess);
#endif

    /* NO CARRIER substring */
    char *c = strstr((char*) modem_input_buffer,"CARR");
    if(c)
    {
        *c = '\0';
        PppoeStopSession(session, "Modem: NO CARRIER");
        return;
    }

    /* reset timer */
    Event_ChangeTimeout(session->ppp_eh, modem_timeout);

    PPPoEPacket packet;
    PPPoEConnection *conn = &session->conn;
    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);
    packet.ethHdr.h_proto = htons(Eth_PPPOE_Session);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_SESS;
    packet.session = conn->session;

    decodeFromPPP(conn, &packet, modem_input_buffer, r);
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
    UINT16_t plen;
    PPPoETag err;
    int elen = strlen(errorMsg);

    memcpy(pads.ethHdr.h_dest, dest, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, source, ETH_ALEN);
    pads.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pads.ver = 1;
    pads.type = 1;
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

/***********************************************************************
*%FUNCTION: sendSessionPacket
*%ARGUMENTS:
* conn -- PPPoE connection
* packet -- the packet to send
* len -- length of data to send
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Transmits a session packet to the peer.
***********************************************************************/
void
sendSessionPacket(PPPoEConnection *conn, PPPoEPacket *packet, int len)
{
    packet->length = htons(len);
    if (clampMss) {
	clampMSS(packet, "outgoing", clampMss);
    }
    if (sendPacket(conn, conn->sessionSocket, packet, len + HDR_SIZE) < 0) {
	if (errno == ENOBUFS) {
	    /* No buffer space is a transient error */
	    syslog(LOG_INFO, " No buffer space is a transient error ");
            return;
	}
        exit(EXIT_FAILURE);
    }
#ifdef DEBUGGING_ENABLED
    if (conn->debugFile) {
	dumpPacket(conn->debugFile, packet, "SENT");
	fprintf(conn->debugFile, "\n");
	fflush(conn->debugFile);
    }
#endif

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
    processEth(fd, (Interface *) data);
}

/**********************************************************************
* %FUNCTION: ModemHandler
* %ARGUMENTS:
*  es -- event selector (ignored)
*  fd -- file descriptor which is readable
*  flags -- ignored
*  data -- Pointer to the Interface structure
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles refresh PPP session data from the modem.
***********************************************************************/
void
ModemHandler(EventSelector *es,
		 int fd,
		 unsigned int flags,
		 void *data)
{
    processModem(fd, (ClientSession *) data);
}

/**********************************************************************
*%FUNCTION: PppoeStartSession
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* init PPP session state and set handlers for eth and modem
***********************************************************************/
static void
PppoeStartSession(ClientSession *session)
{
    int n;
    PPPoEConnection *conn = &session->conn;

#ifdef DEBUGGING_ENABLED
    conn->debugFile = fopen("/tmp/pppoe.debug", "w");
    if (!conn->debugFile) {
        fprintf(stderr, "Could not open %s: %s\n",
                optarg, strerror(errno));
    }
    fprintf(conn->debugFile, "rp-pppoe-%s\n", RP_VERSION);
    fflush(conn->debugFile);
#endif

    /* Initialize connection info */
    memset(conn, 0, sizeof(session->conn));
    conn->discoveryTimeout = PADI_TIMEOUT;
    conn->session = htons((unsigned int) ntohs(session->sess));
    SET_STRING(conn->ifName, session->ethif->name);
    conn->discoveryState = STATE_SESSION;
    for (n=0; n<6; n++) {
        conn->peerEth[n] = (unsigned char) session->eth[n];
    }

    /* Set socket handler for session packets */
    conn->discoverySocket = session->ethif->discovery_sock;
    session->ethif->session_sock = openInterface(conn->ifName, Eth_PPPOE_Session, conn->myEth, NULL);
    session->conn.sessionSocket = session->ethif->session_sock;
    if (eth_timeout.tv_sec != 0)
        session->ethif->session_eh = Event_AddHandlerWithTimeout(event_selector, session->ethif->session_sock,
                EVENT_FLAG_READABLE, eth_timeout, InterfaceHandler, session->ethif);
    else
        session->ethif->session_eh = Event_AddHandler(event_selector, session->ethif->session_sock,
                EVENT_FLAG_READABLE, InterfaceHandler, session->ethif);
    if(!session->ethif->session_eh)
    {
        syslog(LOG_ERR, "Couldn't create event handler for session sosket");
        return;
    }

    /* Set modem handler */
    session->ppp_fd = modemGetFd();
    if (modem_timeout.tv_sec != 0)
        session->ppp_eh = Event_AddHandlerWithTimeout(event_selector, session->ppp_fd,
                EVENT_FLAG_READABLE, modem_timeout, ModemHandler, session);
    else
        session->ppp_eh = Event_AddHandler(event_selector, session->ppp_fd,
                EVENT_FLAG_READABLE, ModemHandler, session);
    if(!session->ppp_eh)
    {
        syslog(LOG_ERR, "Couldn't create event handler for modem fd");
        return;
    }

    /* init session state */
    syslog(LOG_INFO,"Session: init ID=%u", (unsigned int) ntohs(session->sess));
    initPPP();
}

/**********************************************************************
* %FUNCTION: PppoeStopSession
* %ARGUMENTS:
*  ses -- the session
*  reason -- reason session is being stopped.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Kills ppp.
***********************************************************************/
static void
PppoeStopSession(ClientSession *session,
		 char const *reason)
{
    if (modem_is_busy)
    {
        modemHangup();
        modemClose();
    }

    syslog(LOG_INFO,
	   "Session: close ID=%u (client:"
	   "%02x:%02x:%02x:%02x:%02x:%02x on %s; reason: %s",
	   session->sess,
	   session->eth[0], session->eth[1], session->eth[2],
	   session->eth[3], session->eth[4], session->eth[5],
	   session->ethif->name, reason);

    /* Temporary structure for sending PADT's. */
    PPPoEConnection conn;
    memset(&conn, 0, sizeof(conn));
    conn.hostUniq = NULL;
    memcpy(conn.myEth, session->ethif->mac, ETH_ALEN);
    conn.discoverySocket = session->ethif->discovery_sock;
    conn.session = session->sess;
    memcpy(conn.peerEth, session->eth, ETH_ALEN);
    sendPADT(&conn, reason);
    session->flags |= FLAG_SENT_PADT;

    control_session_terminated(session);
    if (pppoe_free_session(session) < 0) {
	return;
    }

    Event_DelHandler(event_selector, session->ethif->session_eh);
    Event_DelHandler(event_selector, session->ppp_eh);

    if (session->pid) {
	kill(session->pid, SIGTERM);
    }
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
*%FUNCTION: PppoeGetSession
*%ARGUMENTS:
* conn -- current connection
*%RETURNS:
* session
*%DESCRIPTION:
* return session associated to a connection
***********************************************************************/
static ClientSession *
PppoeGetSession(int sessionID)
{
    int i;

    /* Get session by ID */
    for (i=0; i<NumSessionSlots-1; i++) {
        if (Sessions[i].sess == sessionID) {
            return &Sessions[i];
         }
    }
    syslog(LOG_ERR, "Session ID %u doesn't match any registered session",
            (unsigned int) ntohs(sessionID));
    return NULL;
}

/**********************************************************************
*%FUNCTION: killAllSessions
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills all ppp PPPoE sessions
***********************************************************************/
void
killAllSessions(void)
{
    ClientSession *sess = BusySessions;
    while(sess) {
	sess->funcs->stop(sess, "Shutting Down");
	sess = sess->next;
    }
#ifdef HAVE_L2TP
    pppoe_close_l2tp_tunnels();
#endif
}

#ifdef HAVE_LICENSE
/**********************************************************************
* %FUNCTION: getFreeMem
* %ARGUMENTS:
*  None
* %RETURNS:
*  The amount of free RAM in kilobytes, or -1 if it could not be
*  determined
* %DESCRIPTION:
*  Reads Linux-specific /proc/meminfo file and extracts free RAM
***********************************************************************/
int
getFreeMem(void)
{
    char buf[512];
    int memfree=0, buffers=0, cached=0;
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return -1;

    while (fgets(buf, sizeof(buf), fp)) {
	if (!strncmp(buf, "MemFree:", 8)) {
	    if (sscanf(buf, "MemFree: %d", &memfree) != 1) {
		fclose(fp);
		return -1;
	    }
	} else if (!strncmp(buf, "Buffers:", 8)) {
	    if (sscanf(buf, "Buffers: %d", &buffers) != 1) {
		fclose(fp);
		return -1;
	    }
	} else if (!strncmp(buf, "Cached:", 7)) {
	    if (sscanf(buf, "Cached: %d", &cached) != 1) {
		fclose(fp);
		return -1;
	    }
	}
    }
    fclose(fp);
    /* return memfree + buffers + cached; */
    return memfree;
}
#endif

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
#ifdef HAVE_LICENSE
    memset(ses->user, 0, MAX_USERNAME_LEN+1);
    memset(ses->realm, 0, MAX_USERNAME_LEN+1);
#endif
#ifdef HAVE_L2TP
    ses->l2tp_ses = NULL;
#endif
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
#ifdef HAVE_L2TP
    ses->l2tp_ses = NULL;
#endif
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
sendHURLorMOTM(PPPoEConnection *conn, char const *url, UINT16_t tag)
{
    PPPoEPacket packet;
    PPPoETag hurl;
    size_t elen;
    unsigned char *cursor = packet.payload;
    UINT16_t plen = 0;

    if (!conn->session) return;
    if (conn->discoverySocket < 0) return;

    if (tag == TAG_HURL) {
	if (strncmp(url, "http://", 7)) {
	    syslog(LOG_WARNING, "sendHURL(%s): URL must begin with http://", url);
	    return;
	}
    } else {
	tag = TAG_MOTM;
    }

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
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
    char buf[SMALLBUF];
    snprintf(buf, SMALLBUF, "%s: %s", str, strerror(errno));
    printErr(buf);
    control_exit();
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
    char buf[1024];
    sprintf(buf, "%.256s: %.256s", str, strerror(errno));
    printErr(buf);
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
    printErr(str);
    control_exit();
    exit(EXIT_FAILURE);
}
