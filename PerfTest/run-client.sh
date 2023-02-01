#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Shell script to run performance-testing CLIENTS on a Linux machine.
#
# Copyright 2001 Roaring Penguin Software Inc.
#
# $Id$

# Each client can create NCONN connections.  The server machine must
# bind NCONN IP addresses so that load can be distributed properly across
# PPPoE sessions.

# This MUST MATCH the setting in run-server.sh!
NCONN=10

# Starting IP address for server.
# This MUST MATCH the setting in run-server.sh!
STARTIP=192.168.43.1

# Number of bytes per test
NBYTES=1000000

# Number of tests per loop
NTESTS=100

# Ethernet card for PPPoE connection
ETH=eth0

# User for PPPoE authentication (password must be in pap-secrets)
USER=dfs

# Set this to zero to use the user-mode PPPoE client (NOT RECOMMENDED)
KERNEL_MODE=0

trap cleanup SIGINT

# Function to get the IP address of an interface
get_ip () {
    IF=$1
    /sbin/ifconfig $IF | grep 'inet addr' | sed -e 's/^.*inet addr://' | awk '{print $1}'
}

# Function to add a number to the last digit of an IP address
add_ip () {
    IP=$1
    inc=$2
    lastdig=`echo $IP | awk -F. '{print $4}'`
    lastdig=`expr $lastdig + $inc`
    firstdigs=`echo $IP | awk -F. '{printf("%d.%d.%d"), $1, $2, $3}'`
    echo $firstdigs.$lastdig
}

# Function to start a PPPoE session and add a route for a given
# destination.  Note!  You MUST have ppp 2.4.0 or newer to support
# the "unit" option.

start_pppoe () {
    SESS=$1
    if test $KERNEL_MODE != 0 ; then
	pppd noipdefault noauth default-asyncmap hide-password \
	    mtu 1492 mru 1492 \
	    noaccomp noccp nobsdcomp nodeflate nopcomp novj \
	    novjccomp user $USER \
	    lcp-echo-interval 30 lcp-echo-failure 3 \
	    plugin /etc/ppp/plugins/rp-pppoe.so $ETH unit $SESS >/dev/null 2>&1
    else
	pppd pty "pppoe -I $ETH -T 80 -U" \
	    noipdefault noauth default-asyncmap hide-password \
	    mtu 1492 mru 1492 \
	    noaccomp noccp nobsdcomp nodeflate nopcomp novj \
	    novjccomp user $USER \
	    lcp-echo-interval 30 lcp-echo-failure 3 \
	    unit $SESS
    fi
    echo -n "Waiting for ppp$SESS to come up"
    for i in 1 2 3 4 5 6 7 8 9 10 ; do
	ifconfig ppp$SESS 2>&1 | grep 'inet addr' > /dev/null 2>&1 && break
	echo -n "."
	sleep 1
    done
    ifconfig ppp$SESS 2>&1 | grep 'inet addr' > /dev/null 2>&1
    if test $? != 0 ; then
	echo ""
	echo "*** Failed to bring up ppp$SESS"
	return
    fi
    IP=`get_ip ppp$SESS`
    echo " up: $IP"
}

# Add a route through a specific PPP interface
add_route () {
    SESS=$1
    ip=`add_ip $STARTIP $SESS`
    route add -host $ip dev ppp$SESS
    echo "Added route to $ip via ppp$SESS"
}

# Run a test
run_test () {
    SESS=$1
    ip=`add_ip $STARTIP $SESS`
    echo "Starting client $SESS"
    ./perf-client $NTESTS $NBYTES $ip > CLIENT-$SESS.log 2>&1 &
}

# Clean up
cleanup () {
    skill pppd
    skill perf-client
    exit 0
}

NCONN1=`expr $NCONN - 1`

# Load kernel modules
modprobe pppoe > /dev/null 2>&1
modprobe ppp_async
modprobe ppp_synctty
modprobe n_hdlc > /dev/null 2>&1

if test $KERNEL_MODE = 0; then
    echo "*** WARNING: Using slow user-mode PPPoE!"
fi

# Start sessions
for i in `seq 0 $NCONN1` ; do
    start_pppoe $i
done

# Add routes
for i in `seq 0 $NCONN1` ; do
    add_route $i
done

# Start tests
for i in `seq 0 $NCONN1` ; do
    run_test $i
done

# Wait for tests to finish
wait

echo "All tests finished."
# Clean up and exit
cleanup
