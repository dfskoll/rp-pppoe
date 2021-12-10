/***********************************************************************
*
* perf-sender-udp.c
*
* Blast UDP packets as fast as we can.
*
* Copyright (C) 1999 by Roaring Penguin Software Inc.
*
* LIC: GPL
*
***********************************************************************/

#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <netdb.h>

#define MAX_SIZE 64000
int port = 3333;
char buf[MAX_SIZE];

char const *
nicenumber(double bps)
{
    static char buffer[128];
    if (bps > 1e9) {
	sprintf(buffer, "%.2fG", bps / 1e9);
    } else if (bps > 1e6) {
	sprintf(buffer, "%.2fM", bps / 1e6);
    } else if (bps > 1e3) {
	sprintf(buffer, "%.2fK", bps / 1e3);
    } else {
	sprintf(buffer, "%.2f", bps);
    }
    return buffer;
}
int
main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in addr;
    struct hostent *he;
    int npackets;
    int packetsize;
    int i;

    if (argc != 4) {
	fprintf(stderr, "Usage: %s npackets packetsize server_ip\n", argv[0]);
	exit(1);
    }
    sscanf(argv[1], "%d", &npackets);
    if (npackets < 1) npackets = 1;
    sscanf(argv[2], "%d", &packetsize);
    if (packetsize > MAX_SIZE) packetsize = MAX_SIZE;

    /* Get address of server */
    he = gethostbyname(argv[3]);
    if (!he) {
	perror("gethostbyname");
	exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr, sizeof(addr.sin_addr));

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	perror("socket");
	exit(1);
    }

    /* Set up buffer */
    for (i=0; i<packetsize; i++) {
	buf[i] = 'A' + (i % 26);
    }
    for (i=0; i<npackets; i++) {
	if (sendto(sock, buf, packetsize, 0,
		   (struct sockaddr *) &addr,
		   sizeof(addr)) < 0) {
	    perror("sendto");
	    exit(1);
	}
    }
    printf("Sent %d UDP packets with %d bytes of data each.\n",
	   npackets, packetsize);
    exit(0);
}
