/***********************************************************************
*
* perf-receiver-udp.c
*
* Receive UDP packets as fast as we can and print statistics.
*
* Copyright (C) 1999 by Roaring Penguin Software Inc.
* Copyright (C) 2018 Dianne Skoll
*
* LIC: GPL
*
***********************************************************************/

#define _POSIX_SOURCE 1

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

static volatile int alarm_happened = 0;
int interval = 5;

void handler_alarm(int sig) {
    alarm_happened = 1;
    alarm(interval);
}

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
    struct sigaction sa;
    int packets = 0;
    int total_packets = 0;
    int bytes = 0;
    int i;
    time_t last, now;
    int diff;
    double bps;

    if (argc != 2) {
	fprintf(stderr, "Usage: %s report_interval\n", argv[0]);
	exit(1);
    }
    sscanf(argv[1], "%d", &interval);
    if (interval < 1) interval = 1;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handler_alarm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGALRM, &sa, NULL) < 0) {
	perror("sigaction");
	exit(1);
    }
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	perror("socket");
	exit(1);
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *) &addr,
	     sizeof(addr)) < 0) {
	return -1;
    }
    alarm(interval);
    last = time(NULL);
    while(1) {
	i = recv(sock, buf, sizeof(buf), 0);
	if (i < 0) {
	    if (errno != EINTR) {
		perror("recv");
		exit(1);
	    }
	}
	if (alarm_happened) {
	    now = time(NULL);
	    diff = now - last;
	    last = now;
	    alarm_happened = 0;
	    if (diff == 0) {
		bps = 0;
	    } else {
		bps = (double) bytes / (double) diff;
		bps *= 8.0;
	    }
	    total_packets += packets;
	    printf("%d cumulative, %d packets, %d bytes in %d seconds (%sbps).\n",
		   total_packets, packets, bytes, diff, nicenumber(bps));
	    packets = 0;
	    bytes = 0;
	}
	if (i >= 0) {
	    packets++;
	    bytes += i;
	}
    }
}
