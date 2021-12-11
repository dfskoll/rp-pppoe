# RP-PPPoE - a PPPoE client, relay and server for Linux

RP-PPPoE is a PPPoE client, relay and server for Linux.  It can run completely
in user-mode or used the Linux kernel's built-in PPPoE support.  Kernel-mode
PPPoE is recommended for much better performance.

# Installation

1. Compile and install pppd if you don't already have it.  If you are
installing from OS packages, make sure to install the PPP development package
as well.

2. Unpack `rp-pppoe` or clone this git repo.

3. Change to source directory: `cd src`

4. Configure: `./configure --enable-plugin`

5. Compile: `make`

6. Install -- this step must be done as root: `make install`

7. Read `doc/HOW-TO-CONNECT`

# Project Home Page

[Project Home Page](https://dianne.skoll.ca/projects/rp-pppoe/)
