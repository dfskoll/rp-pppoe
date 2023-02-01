#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Shell script to run performance-testing SERVER on a Linux machine.
#
# Copyright 2001 Roaring Penguin Software Inc.
# Copyright (C) 2018 Dianne Skoll
#
# $Id$

# Each client can create NCONN connections.  The server machine must
# bind NCONN IP addresses so that load can be distributed properly across
# PPPoE sessions.  For example, if each client can run 10 sessions and
# your server's base IP is 192.168.1.1, then the server will create
# 9 additional clone interfaces with IP addresses 192.168.1.2 through
# 192.168.1.10.  Note that only the last digit is incremented,
# so the last digit must be less than 256-NCONN!

# This MUST MATCH the setting in run-client.sh!
NCONN=10

# Starting IP address for server.
# This MUST MATCH the setting in run-client.sh!
STARTIP=192.168.43.1

# Ethernet interface for server
ETH=eth0

trap cleanup SIGINT

# Function to add a number to the last digit of an IP address
add_ip () {
    IP=$1
    inc=$2
    lastdig=`echo $IP | awk -F. '{print $4}'`
    lastdig=`expr $lastdig + $inc`
    firstdigs=`echo $IP | awk -F. '{printf("%d.%d.%d"), $1, $2, $3}'`
    echo $firstdigs.$lastdig
}

# Function to make slave interfaces with additional IP addresses
make_slaves () {
    IP=$STARTIP
    i=0
    while test $i -lt $NCONN ; do
	ipnew=`add_ip $IP $i`
	ifconfig ${ETH}:$i $ipnew
	echo "Creating slave ${ETH}:$i with addr $ipnew"
	i=`expr $i + 1`
    done
}

# Destroy slaves
destroy_slaves () {
    i=0
    while test $i -lt $NCONN ; do
	ifconfig ${ETH}:$i down
	echo "Destroying slave ${ETH}:$i"
	i=`expr $i + 1`
    done
}

# Clean up
cleanup () {
    destroy_slaves
    exit 0
}

make_slaves
echo "Starting server.  Press Ctrl-C to interrupt."
echo "*** You may start the clients now."
./perf-server
cleanup
