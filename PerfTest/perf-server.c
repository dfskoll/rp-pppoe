/***********************************************************************
*
* perftest/perf-server.c
*
* A simple server which reads bytes from a client
*
* Copyright (C) 2001 by Roaring Penguin Software Inc.
* Copyright (C) 2018 Dianne Skoll
*
* SPDX-License-Identifier: GPL-2.0-or-later
***********************************************************************/

#define _POSIX_SOURCE 1 /* For sigaction defines */
#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>

#define CHUNK_SIZE 65536
int port = 3333;
char buf[CHUNK_SIZE];

void
sigchld(int sig)
{
    while(waitpid(-1, NULL, WNOHANG) > 0) {
    }
}
void
serve(int s) {
    int n;
    n = 1;
    while(n) {
	n = read(s, buf, CHUNK_SIZE);
	if (n < 0) {
	    perror("read");
	    return;
	}
    }
}
int
main(int argc, char *argv[]) {
    int lsock;
    int asock;
    pid_t pid;
    int opt;
    struct sockaddr_in addr;
    struct sockaddr_in peerAddr;
    socklen_t len;
    struct sigaction act;

    /* Set up SIGCHLD handler */
    /* Set signal handler for SIGCHLD */
    act.sa_handler = sigchld;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &act, NULL) < 0) {
	perror("sigaction");
	exit(1);
    }

    /* Create listening socket */
    lsock = socket(PF_INET, SOCK_STREAM, 0);
    if (lsock < 0) {
	perror("socket");
	exit(1);
    }
    opt = 1;

    /* Reuse port */
    if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    /* Bind the socket */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = (uint32_t) INADDR_ANY;
    if (bind(lsock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    /* Listen */
    if (listen(lsock, 10) < 0) {
	perror("listen");
	exit(1);
    }

    /* Server loop */
    while (1) {
	len = sizeof(peerAddr);
	asock = accept(lsock, (struct sockaddr *) &peerAddr, &len);
	if (asock < 0) {
	    if (errno == EINTR) continue;
	    perror("accept");
	    exit(1);
	}
	printf("Accepted connection from %s\n", inet_ntoa(peerAddr.sin_addr));
	fflush(stdout);
	pid = fork();
	if (pid < 0) {
	    perror("fork");
	    close(lsock);
	    continue;
	}
	if (pid == 0) {
	    /* In child */
	    serve(asock);
	    close(asock);
	    exit(0);
	}
	/* In parent */
	close(asock);
    }
}

