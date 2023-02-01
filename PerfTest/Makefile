# Makefile for performance-testing software
# SPDX-License-Identifier: GPL-2.0-or-later

CC=gcc
CFLAGS=-O2 -ansi -pedantic -Wall -Wstrict-prototypes

MANIFEST=PerfTest/README.txt PerfTest/Makefile PerfTest/perf-client.c	    \
	PerfTest/perf-server.c						    \
	PerfTest/run-client.sh PerfTest/run-server.sh PerfTest/perf-doc.pdf

all: perf-server perf-client perf-sender-udp perf-receiver-udp

perf-server: perf-server.c
	$(CC) $(CFLAGS) -o perf-server perf-server.c

perf-sender-udp: perf-sender-udp.c
	$(CC) $(CFLAGS) -o perf-sender-udp perf-sender-udp.c

perf-receiver-udp: perf-receiver-udp.c
	$(CC) $(CFLAGS) -o perf-receiver-udp perf-receiver-udp.c

client: perf-client.c
	$(CC) $(CFLAGS) -o perf-client perf-client.c

clean: FORCE
	rm -f *~ *.o perf-server perf-client

distro: perf-doc.pdf FORCE
	(cd ..; tar cf PerfTest.tar $(MANIFEST); gzip -f -v -9 PerfTest.tar)


perf-doc.pdf: setup.fig perf-doc.tex
	fig2dev -L eps setup.fig > setup.eps
	epstopdf setup.eps
	pdflatex perf-doc.tex
	pdflatex perf-doc.tex

FORCE:

.phony: FORCE
