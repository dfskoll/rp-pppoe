/**********************************************************************
*
* pppoe-server.h
*
* Definitions for PPPoE server
*
* Copyright (C) 2001-2012 Roaring Penguin Software Inc.
* Copyright (C) 2018-2023 Dianne Skoll
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
* $Id$
*
***********************************************************************/

#include "config.h"
#include "event.h"
#include "pppoe.h"

#if defined(HAVE_LINUX_IF_H)
#include <linux/if.h>
#elif defined(HAVE_NET_IF_H)
#include <net/if.h>
#endif

#define MAX_USERNAME_LEN 31
/* An Ethernet interface */
typedef struct {
    char name[IFNAMSIZ+1];	/* Interface name */
    int sock;			/* Socket for discovery frames */
    unsigned char mac[ETH_ALEN]; /* MAC address */
    EventHandler *eh;		/* Event handler for this interface */
    uint16_t mtu;               /* MTU of interface */
} Interface;

#define FLAG_RECVD_PADT      1
#define FLAG_USER_SET        2
#define FLAG_IP_SET          4
#define FLAG_SENT_PADT       8

/* Only used if we are an L2TP LAC or LNS */
#define FLAG_ACT_AS_LAC      256
#define FLAG_ACT_AS_LNS      512

/* Forward declaration */
struct ClientSessionStruct;

/* Dispatch table for session-related functions.  We call different
   functions for L2TP-terminated sessions than for locally-terminated
   sessions. */
typedef struct PppoeSessionFunctionTable_t {
    /* Stop the session */
    void (*stop)(struct ClientSessionStruct *ses, char const *reason);

    /* Return 1 if session is active, 0 otherwise */
    int (*isActive)(struct ClientSessionStruct *ses);

    /* Describe a session in human-readable form */
    char const * (*describe)(struct ClientSessionStruct *ses);
} PppoeSessionFunctionTable;

extern PppoeSessionFunctionTable DefaultSessionFunctionTable;

/* A client session */
typedef struct ClientSessionStruct {
    struct ClientSessionStruct *next; /* In list of free or active sessions */
    PppoeSessionFunctionTable *funcs; /* Function table */
    pid_t pid;			/* PID of child handling session */
    Interface *ethif;		/* Ethernet interface */
    unsigned char myip[IPV4ALEN]; /* Local IP address */
    unsigned char peerip[IPV4ALEN]; /* Desired IP address of peer */
    uint16_t sess;		/* Session number */
    unsigned char eth[ETH_ALEN]; /* Peer's Ethernet address */
    unsigned int flags;		/* Various flags */
    time_t startTime;		/* When session started */
    char const *serviceName;	/* Service name */
    uint16_t requested_mtu;     /* Requested PPP_MAX_PAYLOAD  per RFC 4638 */
} ClientSession;

/* Hack for daemonizing */
#define CLOSEFD 64

/* Initial Max. number of interfaces to listen on */
#define INIT_INTERFACES 8

/* Max. 64 sessions by default */
#define DEFAULT_MAX_SESSIONS 64

/* An array of client sessions */
extern ClientSession *Sessions;

/* Interfaces we're listening on */
extern Interface *interfaces;
extern int NumInterfaces;

/* The number of session slots */
extern size_t NumSessionSlots;

/* The number of active sessions */
extern size_t NumActiveSessions;

/* Offset of first session */
extern size_t SessOffset;

/* Access concentrator name */
extern char *ACName;

extern unsigned char LocalIP[IPV4ALEN];
extern unsigned char RemoteIP[IPV4ALEN];

/* Do not create new sessions if free RAM < 10MB (on Linux only!) */
#define MIN_FREE_MEMORY 10000

/* Do we increment local IP for each connection? */
extern int IncrLocalIP;

/* Free sessions */
extern ClientSession *FreeSessions;

/* When a session is freed, it is added to the end of the free list */
extern ClientSession *LastFreeSession;

/* Busy sessions */
extern ClientSession *BusySessions;

extern EventSelector *event_selector;
extern int GotAlarm;

extern void setAlarm(unsigned int secs);
extern void killAllSessions(void);
extern void serverProcessPacket(Interface *i);
extern void processPADT(Interface *ethif, PPPoEPacket *packet, int len);
extern void processPADR(Interface *ethif, PPPoEPacket *packet, int len);
extern void processPADI(Interface *ethif, PPPoEPacket *packet, int len);
extern void usage(char const *msg);
extern ClientSession *pppoe_alloc_session(void);
extern int pppoe_free_session(ClientSession *ses);
extern void sendHURLorMOTM(PPPoEConnection *conn, char const *url, uint16_t tag);

