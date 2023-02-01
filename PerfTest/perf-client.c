/***********************************************************************
*
* perftest/perf-client.c
*
* A simple client which writes bytes from a server
*
* Copyright (C) 2001 by Roaring Penguin Software Inc.
* Copyright (C) 2018 Dianne Skoll
*
* SPDX-License-Identifier: GPL-2.0-or-later
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
#include <string.h>

#define CHUNK_SIZE 655360
int port = 3333;
char buf[CHUNK_SIZE];

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
    struct timeval start, end;
    long sec_diff, usec_diff, msecs;
    int nbytes;
    int i;
    int bytesleft;
    int towrite;
    double bitspersec;
    int ntests;
    int testno;
    double total_bps = 0.0;

    /* Usage: perf-client ntests nbytes machine_or_ip */
    if (argc != 4) {
	fprintf(stderr, "Usage: %s ntests nbytes server_ip\n", argv[0]);
	exit(1);
    }
    sscanf(argv[1], "%d", &ntests);
    if (ntests < 1) ntests = 1;
    sscanf(argv[2], "%d", &towrite);
    if (towrite < CHUNK_SIZE) towrite = CHUNK_SIZE;

    /* Get address of server */
    he = gethostbyname(argv[3]);
    if (!he) {
	perror("gethostbyname");
	exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
	perror("socket");
	exit(1);
    }
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	perror("connect");
	exit(1);
    }
    /* Set up buffer */
    for (i=0; i<CHUNK_SIZE; i++) {
	buf[i] = 'A' + (i % 26);
    }
    for (testno=0; testno<ntests; testno++) {
	bytesleft = towrite;
	gettimeofday(&start, NULL);
	while(bytesleft) {
	    nbytes = write(sock, buf, (bytesleft < CHUNK_SIZE) ? bytesleft : CHUNK_SIZE);
	    if (nbytes <= 0) {
		perror("write");
		exit(1);
	    }
	    bytesleft -= nbytes;
	}
	gettimeofday(&end, NULL);

	sec_diff = end.tv_sec - start.tv_sec;
	usec_diff = end.tv_usec - start.tv_usec;
	if (usec_diff < 0) {
	    sec_diff --;
	    usec_diff += 1000000;
	}
	msecs = 1000 * sec_diff + (usec_diff / 1000);
	bitspersec = (8000.0 * towrite) / (double) msecs;

	printf("%10d bytes %6ld milliseconds %12d bps (%s)\n",
	       towrite, msecs, (int) bitspersec, nicenumber(bitspersec));
	total_bps += bitspersec;
	fflush(stdout);
    }
    total_bps /= (double) ntests;
    printf("\nAverage speed: %12d bps (%s)\n",
	   (int) total_bps, nicenumber(total_bps));
    exit(0);
}
