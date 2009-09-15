AC_INIT([netdiscover], [0.3-beta7], [jpenalbae@gmail.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC

dnl Checks for header files.
dnl check for pcap.h
AC_CHECK_HEADER(pcap.h,,
        AC_MSG_ERROR(Cannot find pcap.h - You need libpcap installed.))

dnl check for libnet.h
AC_CHECK_HEADER(libnet.h,,
        AC_MSG_ERROR(Cannot find libnet.h - You need libnet 1.1.x installed.))

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])
AC_OUTPUT

