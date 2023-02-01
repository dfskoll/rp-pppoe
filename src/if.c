/***********************************************************************
*
* if.c
*
* Implementation of user-space PPPoE redirector for Linux.
*
* Functions for opening a raw socket and reading/writing raw Ethernet frames.
*
* Copyright (C) 2000-2012 by Roaring Penguin Software Inc.
* Copyright (C) 2018-2023 Dianne Skoll
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
***********************************************************************/

#include <unistd.h>

#include <net/ethernet.h>

#include <sys/ioctl.h>
#include <syslog.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <net/if_arp.h>

#include "pppoe.h"
#include <linux/if.h>
#include <linux/if_packet.h>

/* Initialize frame types to RFC 2516 values.  Some broken peers apparently
   use different frame types... sigh... */

uint16_t Eth_PPPOE_Discovery = ETH_PPPOE_DISCOVERY;
uint16_t Eth_PPPOE_Session   = ETH_PPPOE_SESSION;

/**********************************************************************
*%FUNCTION: etherType
*%ARGUMENTS:
* packet -- a received PPPoE packet
*%RETURNS:
* ethernet packet type (see /usr/include/net/ethertypes.h)
*%DESCRIPTION:
* Checks the ethernet packet header to determine its type.
* We should only be receiving DISCOVERY and SESSION types if the BPF
* is set up correctly.  Logs an error if an unexpected type is received.
* Note that the ethernet type names come from "pppoe.h" and the packet
* packet structure names use the LINUX dialect to maintain consistency
* with the rest of this file.  See the BSD section of "pppoe.h" for
* translations of the data structure names.
***********************************************************************/
uint16_t
etherType(PPPoEPacket *packet)
{
    uint16_t type = (uint16_t) ntohs(packet->ethHdr.h_proto);
    if (type != Eth_PPPOE_Discovery && type != Eth_PPPOE_Session) {
	syslog(LOG_ERR, "Invalid ether type 0x%x", type);
    }
    return type;
}

/**********************************************************************
*%FUNCTION: openInterface
*%ARGUMENTS:
* ifname -- name of interface
* type -- Ethernet frame type
* hwaddr -- if non-NULL, set to the hardware address
* mtu    -- if non-NULL, set to the MTU
*%RETURNS:
* A raw socket for talking to the Ethernet card.  Exits on error.
*%DESCRIPTION:
* Opens a raw Ethernet socket
***********************************************************************/
int
openInterface(char const *ifname, uint16_t type, unsigned char *hwaddr, uint16_t *mtu)
{
    int optval=1;
    int fd;
    struct ifreq ifr;
    int domain, stype;

#ifdef HAVE_STRUCT_SOCKADDR_LL
    struct sockaddr_ll sa;
#else
    struct sockaddr sa;
#endif

    memset(&sa, 0, sizeof(sa));

#ifdef HAVE_STRUCT_SOCKADDR_LL
    domain = PF_PACKET;
    stype = SOCK_RAW;
#else
    domain = PF_INET;
    stype = SOCK_PACKET;
#endif

    if ((fd = socket(domain, stype, htons(type))) < 0) {
	/* Give a more helpful message for the common error case */
	if (errno == EPERM) {
	    rp_fatal("Cannot create raw socket -- pppoe must be run as root.");
	}
	fatalSys("socket");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
	fatalSys("setsockopt");
    }

    /* Fill in hardware address */
    if (hwaddr) {
	rp_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
	    fatalSys("ioctl(SIOCGIFHWADDR)");
	}
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
#ifdef ARPHRD_ETHER
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
	    char buffer[256];
	    sprintf(buffer, "Interface %.16s is not Ethernet", ifname);
	    rp_fatal(buffer);
	}
#endif
	if (NOT_UNICAST(hwaddr)) {
	    char buffer[256];
	    sprintf(buffer,
		    "Interface %.16s has broadcast/multicast MAC address??",
		    ifname);
	    rp_fatal(buffer);
	}
    }

    /* Sanity check on MTU */
    rp_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
	fatalSys("ioctl(SIOCGIFMTU)");
    }
    if (ifr.ifr_mtu < ETH_DATA_LEN) {
	printErr("Interface %.16s has MTU of %d -- should be %d.  You may have serious connection problems.",
		ifname, ifr.ifr_mtu, ETH_DATA_LEN);
    }
    if (mtu) *mtu = ifr.ifr_mtu;

#ifdef HAVE_STRUCT_SOCKADDR_LL
    /* Get interface index */
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(type);

    rp_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	fatalSys("ioctl(SIOCFIGINDEX): Could not get interface index");
    }
    sa.sll_ifindex = ifr.ifr_ifindex;

#else
    strcpy(sa.sa_data, ifname);
#endif

    /* We're only interested in packets on specified interface */
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
	fatalSys("bind");
    }

    return fd;
}

/***********************************************************************
*%FUNCTION: sendPacket
*%ARGUMENTS:
* sock -- socket to send to
* pkt -- the packet to transmit
* size -- size of packet (in bytes)
*%RETURNS:
* 0 on success; -1 on failure
*%DESCRIPTION:
* Transmits a packet
***********************************************************************/
int
sendPacket(PPPoEConnection *conn, int sock, PPPoEPacket *pkt, int size)
{
#if defined(HAVE_STRUCT_SOCKADDR_LL)
    if (send(sock, pkt, size, 0) < 0 && (errno != ENOBUFS)) {
	sysErr("send (sendPacket)");
	return -1;
    }
#else
    struct sockaddr sa;

    if (!conn) {
	rp_fatal("relay and server not supported on Linux 2.0 kernels");
    }
    strcpy(sa.sa_data, conn->ifName);
    if (sendto(sock, pkt, size, 0, &sa, sizeof(sa)) < 0) {
	sysErr("sendto (sendPacket)");
	return -1;
    }
#endif
    return 0;
}

/***********************************************************************
*%FUNCTION: receivePacket
*%ARGUMENTS:
* sock -- socket to read from
* pkt -- place to store the received packet
* size -- set to size of packet in bytes
*%RETURNS:
* >= 0 if all OK; < 0 if error
*%DESCRIPTION:
* Receives a packet
***********************************************************************/
int
receivePacket(int sock, PPPoEPacket *pkt, int *size)
{
    if ((*size = recv(sock, pkt, sizeof(PPPoEPacket), 0)) < 0) {
	sysErr("recv (receivePacket)");
	return -1;
    }
    return 0;
}
