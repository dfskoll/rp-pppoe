/***********************************************************************
*
* pppoe-sniff.c
*
* Sniff a network for likely-looking PPPoE frames and deduce the
* command-line options to add to pppoe.  USE AT YOUR OWN RISK.
*
* Copyright (C) 2000-2018 by Roaring Penguin Software Inc.
* Copyright (C) 2018-2023 Dianne Skoll
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
***********************************************************************/

#define _GNU_SOURCE 1

#include <getopt.h>

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "pppoe.h"

/* Default interface if no -I option given */
#define DEFAULT_IF "eth0"

/* Global vars */
int SeenPADR = 0;
int SeenSess = 0;
uint16_t SessType, DiscType;

char *IfName = NULL;		/* Interface name */
char *ServiceName = NULL;	/* Service name   */

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
    case TAG_SERVICE_NAME:
	ServiceName = malloc(len+1);
	if (ServiceName) {
	    memcpy(ServiceName, data, len);
	    ServiceName[len] = 0;
	}
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
* Prints a message plus the errno value to stderr and exits.
***********************************************************************/
void
fatalSys(char const *str)
{
    printErr("%.256s: %.256s", str, strerror(errno));
    exit(EXIT_FAILURE);
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
*%FUNCTION: usage
*%ARGUMENTS:
* argv0 -- program name
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints usage information and exits.
***********************************************************************/
void
usage(char const *argv0)
{
    fprintf(stderr, "Usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "   -I if_name     -- Specify interface (default %s.)\n",
	    DEFAULT_IF);
    fprintf(stderr, "   -V             -- Print version and exit.\n");
    fprintf(stderr, "\nPPPoE Version %s, Copyright (C) 2000 Roaring Penguin Software Inc.\n", RP_VERSION);
    fprintf(stderr, "              %*s  Copyright (C) 2018-2023 Dianne Skoll\n", (int) strlen(RP_VERSION), "");
    fprintf(stderr, "PPPoE comes with ABSOLUTELY NO WARRANTY.\n");
    fprintf(stderr, "This is free software, and you are welcome to redistribute it under the terms\n");
    fprintf(stderr, "of the GNU General Public License, version 2 or any later version.\n");
    fprintf(stderr, "https://dianne.skoll.ca/projects/rp-pppoe/\n");
    exit(EXIT_SUCCESS);
}

/**********************************************************************
*%FUNCTION: main
*%ARGUMENTS:
* argc, argv -- count and values of command-line arguments
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Main program
***********************************************************************/
int
main(int argc, char *argv[])
{
    int opt;
    int sock;
    PPPoEPacket pkt;
    int size;

    if (getuid() != geteuid() ||
	getgid() != getegid()) {
	fprintf(stderr, "SECURITY WARNING: pppoe-sniff will NOT run suid or sgid.  Fix your installation.\n");
	exit(EXIT_FAILURE);
    }

    while((opt = getopt(argc, argv, "I:V")) != -1) {
	switch(opt) {
	case 'I':
	    SET_STRING(IfName, optarg);
	    break;
	case 'V':
	    printf("pppoe-sniff: RP-PPPoE Version %s\n", RP_VERSION);
	    exit(EXIT_SUCCESS);
	default:
	    usage(argv[0]);
	}
    }

    /* Pick a default interface name */
    if (!IfName) {
	IfName = DEFAULT_IF;
    }

    sock = openInterface(IfName, ETH_P_ALL,  NULL, NULL);

    /* We assume interface is in promiscuous mode -- use "ip link
       show" to ensure this */
    fprintf(stderr, "Sniffing for PADR.  Start your connection on another machine...\n");
    while (!SeenPADR) {
	if (receivePacket(sock, &pkt, &size) < 0) continue;
	if (ntohs(pkt.length) + HDR_SIZE > size) continue;
	if (PPPOE_VER(pkt.vertype) != 1 || PPPOE_TYPE(pkt.vertype) != 1) continue;
	if (pkt.code != CODE_PADR)               continue;

	/* Looks promising... parse it */
	if (parsePacket(&pkt, parsePADRTags, NULL) < 0) {
	    continue;
	}
	DiscType = ntohs(pkt.ethHdr.h_proto);
	fprintf(stderr, "\nExcellent!  Sniffed a likely-looking PADR.\n");
	break;
    }

    while (!SeenSess) {
	if (receivePacket(sock, &pkt, &size) < 0) continue;
	if (ntohs(pkt.length) + HDR_SIZE > size) continue;
	if (PPPOE_VER(pkt.vertype) != 1 || PPPOE_TYPE(pkt.vertype) != 1) continue;
	if (pkt.code != CODE_SESS)               continue;

	/* Cool! */
	SessType = ntohs(pkt.ethHdr.h_proto);
	break;
    }

    fprintf(stderr, "Wonderful!  Sniffed a likely-looking session packet.\n");
    if ((ServiceName == NULL || *ServiceName == 0) &&
	DiscType == ETH_PPPOE_DISCOVERY &&
	SessType == ETH_PPPOE_SESSION) {
	fprintf(stderr, "\nGreat!  It looks like a standard PPPoE service.\nYou should not need any special command-line options.\n");
	return 0;
    }

    fprintf(stderr, "\nOK, looks like you need extra arguments for 'pppoe'.\n");
    if (ServiceName != NULL && *ServiceName != 0) {
	fprintf(stderr, "-S '%s'\n", ServiceName);
    }
    if (DiscType != ETH_PPPOE_DISCOVERY || SessType != ETH_PPPOE_SESSION) {
	fprintf(stderr, "-f %x:%x\n", DiscType, SessType);
    }
    return 0;
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
