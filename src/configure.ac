dnl Process this file with autoconf to produce a configure script.
dnl SPDX-License-Identifier: GPL-2.0-or-later
AC_INIT
AC_CONFIG_SRCDIR([pppoe.c])

dnl pppd directory for kernel-mode PPPoE
PPPD_DIR=ppp-2.4.1.pppoe2

AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT(/usr)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_CHECK_TOOL([AR],[ar],[/bin/false])

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(net/if_arp.h sys/uio.h net/ethernet.h linux/if_packet.h)
AC_CHECK_HEADERS(linux/if.h, [], [], [#include<sys/socket.h>])
AC_CHECK_HEADERS(linux/if_pppox.h, [], [],
[
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
])

dnl Check for sockaddr_ll
AC_MSG_CHECKING(for struct sockaddr_ll)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
]], [[struct sockaddr_ll sa;]])],[ac_cv_struct_sockaddr_ll=yes],[ac_cv_struct_sockaddr_ll=no])
AC_MSG_RESULT($ac_cv_struct_sockaddr_ll)

if test "$ac_cv_struct_sockaddr_ll" = yes ; then
AC_DEFINE(HAVE_STRUCT_SOCKADDR_LL)
fi

dnl Check for N_HDLC line discipline
AC_MSG_CHECKING(for N_HDLC line discipline)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <pty.h>
]], [[int x = N_HDLC;]])],[ac_cv_n_hdlc=yes],[ac_cv_n_hdlc=no])
AC_MSG_RESULT($ac_cv_n_hdlc)
if test "$ac_cv_n_hdlc" = yes ; then
AC_DEFINE(HAVE_N_HDLC)
fi

AC_ARG_ENABLE(plugin, [  --enable-plugin=pppd_src_path   build pppd plugin], ac_cv_pluginpath=$enableval, ac_cv_pluginpath=no)
AC_ARG_ENABLE(debugging, [  --disable-debugging             disable debugging code], ac_cv_debugging=$enableval, ac_cv_debugging=yes)
AC_ARG_ENABLE(static, [  --enable-static                 Build static executables], ac_cv_static=$enableval, ac_cv_static=no)

dnl If we were given "--enable-plugin" without a path, take a stab at where
dnl the pppd source code might be.

if test "$ac_cv_pluginpath" = "yes" ; then
    for i in /usr/include /usr/local/include `echo $CPATH | sed -e 's/:/ /g'`; do
	if test -r $i/pppd/pppd.h; then
	    ac_cv_pluginpath=$i
	fi
    done
fi

if test "$ac_cv_pluginpath" = "yes" ; then
    echo "*** Could not find pppd/pppd.h anywhere... not building plugin"
    ac_cv_pluginpath=no
fi

AC_ARG_ENABLE(licenses, [  --enable-licenses=lic_path      build commercial version], ac_cv_licpath=$enableval, ac_cv_licpath=no)

PPPOE_SERVER_DEPS=""

dnl Determine whether or not to build Linux pppd plugin
LINUX_KERNELMODE_PLUGIN=""
PPPD_INCDIR=""
if test "$ac_cv_header_linux_if_pppox_h" = yes ; then
	if test "$ac_cv_pluginpath" != no ; then
		LINUX_KERNELMODE_PLUGIN=rp-pppoe.so
		AC_DEFINE(HAVE_LINUX_KERNEL_PPPOE)
		PPPD_INCDIR=$ac_cv_pluginpath
	fi
fi

if test "$PPPD_INCDIR" = "" ; then
   PPPD_INCDIR=/usr/include
fi

if test "$ac_cv_debugging" = "yes" ; then
   AC_DEFINE(DEBUGGING_ENABLED)
fi

AC_SUBST(LINUX_KERNELMODE_PLUGIN)
AC_SUBST(PPPD_INCDIR)
AC_SUBST(PPPD_H)

dnl Determine whether or not to build PPPoE relay
PPPOE_RELAY=""
if test "`uname -s`" = "Linux" ; then
	PPPOE_RELAY=pppoe-relay
fi
AC_SUBST(PPPOE_RELAY)

dnl Checks for library functions.
AC_FUNC_MEMCMP

AC_CHECK_FUNCS(select socket strerror strtol strlcpy)
AC_PROG_INSTALL

dnl Check for location of ip
AC_PATH_PROG(IP, ip, NOTFOUND, $PATH:/bin:/sbin:/usr/bin:/usr/sbin)

dnl Check for location of pppd
AC_PATH_PROG(PPPD, pppd, NOTFOUND, $PATH:/sbin:/usr/sbin:/usr/local/sbin)

dnl Check for setsid (probably Linux-specific)
AC_PATH_PROG(SETSID, setsid, "", $PATH:/sbin:/usr/sbin:/usr/local/sbin)

dnl Check for an "id" which accepts "-u" option -- hack for Solaris.
AC_PATH_PROG(ID, id, "", /usr/xpg4/bin:$PATH)

dnl Check for Linux-specific kernel support for PPPoE
AC_MSG_CHECKING(for Linux 2.4.X kernel-mode PPPoE support)
AC_CACHE_VAL(ac_cv_linux_kernel_pppoe,[
if test "`uname -s`" = "Linux" ; then
if test $cross_compiling = "no"; then

dnl Do a bunch of modprobes.  Can't hurt; might help.
modprobe ppp_generic > /dev/null 2>&1
modprobe ppp_async > /dev/null 2>&1
modprobe n_hdlc > /dev/null 2>&1
modprobe ppp_synctty > /dev/null 2>&1
modprobe pppoe > /dev/null 2>&1
fi
AC_RUN_IFELSE([AC_LANG_SOURCE([[#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_pppox.h>
int main()
{
	if (socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OE) >= 0) return 0; else return 1;
}
]])],[ac_cv_linux_kernel_pppoe=yes],[ac_cv_linux_kernel_pppoe=no],[ac_cv_linux_kernel_pppoe=no; echo "cross-compiling, default: "])
else
	ac_cv_linux_kernel_pppoe=no
fi
])

AC_MSG_RESULT($ac_cv_linux_kernel_pppoe)

if test "$ac_cv_linux_kernel_pppoe" != yes ; then
   if test "$LINUX_KERNELMODE_PLUGIN" = rp-pppoe.so; then
      echo "*** Your kernel does not appear to have built-in PPPoE support,"
      echo "*** but I will build the kernel-mode plugin anyway."
   fi
fi

dnl GCC warning level
if test "$GCC" = yes; then
	CFLAGS="$CFLAGS -fno-strict-aliasing -Wall -Wstrict-prototypes"
fi

dnl If we couldn't find pppd, die
if test "$PPPD" = "NOTFOUND"; then
        AC_MSG_WARN([*** Oops!  I couldn't find pppd, the PPP daemon anywhere.])
	AC_MSG_WARN([*** You must install pppd, version 2.3.10 or later.])
	AC_MSG_WARN([*** I will keep going, but it may not work.])
	PPPD=pppd
fi

# Sigh... got to fix this up for tcl
test "x$prefix" = xNONE && prefix=$ac_default_prefix
# Let make expand exec_prefix.
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'

# Fully resolve WRAPPER for Tcl script.
WRAPPER=${sbindir}/pppoe-wrapper
eval "WRAPPER=${WRAPPER}"
eval "WRAPPER=${WRAPPER}"
AC_SUBST(WRAPPER)

# Determine what targets to build
TARGETS="pppoe pppoe-server pppoe-sniff pppoe-relay"

# plugin is built only if we have kernel support
if test -n "$LINUX_KERNELMODE_PLUGIN" ; then
	TARGETS="$TARGETS $LINUX_KERNELMODE_PLUGIN"
	mkdir plugin > /dev/null 2>&1
fi

EXTRACONFIGS=""

RDYNAMIC=""

if test "$ac_cv_static" = "yes" ; then
   STATIC=-static
else
   STATIC=""
fi

LIBEVENT=../libevent
AC_SUBST(TARGETS)
AC_SUBST(PPPOE_SERVER_DEPS)
AC_SUBST(RDYNAMIC)
AC_SUBST(LIBEVENT)
AC_SUBST(LDFLAGS)
AC_SUBST(STATIC)

datadir_evaluated=`eval echo $datadir`
AC_SUBST(datadir_evaluated)

AC_CONFIG_FILES([Makefile libevent/Makefile $EXTRACONFIGS])
AC_OUTPUT

AC_MSG_RESULT([On this platform, the following targets will be built:])
AC_MSG_RESULT([$TARGETS])
AC_MSG_RESULT([Type 'make' to compile the software.])
