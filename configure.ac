#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([hadm], [0.1], [cxy@skybility.com])
# AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_INIT_AUTOMAKE([-Wall foreign])

AC_CONFIG_MACRO_DIR([m4])

AC_PREFIX_DEFAULT(/opt/hadm)

AC_CONFIG_SUBDIRS([libs/zlog-master])
AC_CONFIG_SUBDIRS([libs/libevent-2.0.21-stable])

AC_CONFIG_SRCDIR([src/hadm_main.c])
AC_CONFIG_HEADERS([config.h])

if test x"$prefix" == xNONE; then
	HADM_PREFIX="/opt/hadm"
else
	HADM_PREFIX="$prefix"
fi

AC_DEFINE_UNQUOTED([PREFIX], ["$HADM_PREFIX"], [hadm prefix])

AC_ARG_ENABLE([compress],
		[AS_HELP_STRING([--enable-compress], [Enable Compress])],
		[ENABLE_COMPRESS=$enableval;AC_DEFINE([HADM_COMPRESS], [1], [enable compress])])

AC_ARG_ENABLE([debug],
		[AS_HELP_STRING([--enable-debug], [Enable Debug])],
		[ENABLE_DEBUG=$enableval;AC_DEFINE([HADM_DEBUG], [1], [enable debug])],
		[AC_DEFINE([HADM_DEBUG], [1], [enable debug])])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
# AC_CHECK_LIB([pthread], [pthread_create], [], [ echo "Error: need pthread" exit -1])

# AC_CHECK_LIB([event], [event_base_new], [], [ echo "Error: need libevent" exit -1])

AC_CHECK_LIB([xml2], [xmlParseFile], [], [
		echo "Error: need libxml2"
		exit -1])

AC_CHECK_LIB([z], [compress], [], [
		echo "Error: need zlib"
		exit -1])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netdb.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime gethostname memset select socket])

PACKET_NAME=`sed -n -e '/P_CTRL_START/,/P_TYPE_MAX/{s/^[[[:space:]]]\+\([[_A-Z0-9]]\+\).*,/[[\1]] = "\1",/p}' ${srcdir}/include/packet.inc`
AC_SUBST(PACKET_NAME)

CSTATE_NAME=`sed -n -e '/C_STOPPED/,/C_SPLITBRAIN/{s/[[[:space:]]]*\(C_\)\(.*\),/[[\1\2]] = "\L\2",/p}' ${srcdir}/include/common.inc`
AC_SUBST(CSTATE_NAME)

DATASTATE_NAME=`sed -n -e '/DATA_UPTODATE/,/DATA_CORRUPT/{s/[[[:space:]]]*\(DATA_\)\(.*\),/[[\1\2]] = "\L\2",/p}' ${srcdir}/include/common.inc`
AC_SUBST(DATASTATE_NAME)

DSTATE_NAME=`sed -n -e '/D_CONSISTENT/,/D_INCONSISTENT/{s/[[[:space:]]]*\(D_\)\(.*\),/[[\1\2]] = "\L\2",/p}' ${srcdir}/include/common.inc`
AC_SUBST(DSTATE_NAME)

NSTATE_NAME=`sed -n -e '/N_DISCONNECT/,/N_CONNECT/{s/[[[:space:]]]*\(N_\)\(.*\),/[[\1\2]] = "\L\2",/p}' ${srcdir}/include/common.inc`
AC_SUBST(NSTATE_NAME)

ROLE_NAME=`sed -n -e '/R_SECONDARY/,/R_PRIMARY/{s/[[[:space:]]]*\(R_\)\(.*\),/[[\1\2]] = "\L\2",/p}' ${srcdir}/include/common.inc`
AC_SUBST(ROLE_NAME)

DEV_STATE_NAME=`sed -n -e '/DEV_DOWN/,/DEV_UP/{s/[[[:space:]]]*\(DEV_\)\(.*\),/[[\1\2]] = "\L\2",/p}' ${srcdir}/include/common.inc`
AC_SUBST(DEV_STATE_NAME)

PROTO_NAME=`sed -n -e '/PROTO_ASYNC/,/PROTO_SYNC/{s/[[[:space:]]]*\(PROTO_\)\(.*\),/[[\1\2]] = "\L\2",/p}' ${srcdir}/include/common.inc`
AC_SUBST(PROTO_NAME)

GIT_COMMIT_ID=`git log -1 --pretty=format:"%H"`
AC_DEFINE_UNQUOTED([GIT_COMMIT], ["$GIT_COMMIT_ID"], [git commit id])
AC_SUBST(GIT_COMMIT_ID)

AC_CONFIG_FILES([include/common_string.h])

AC_CONFIG_FILES([Makefile
		conf/Makefile
		libs/Makefile
		src/Makefile])

AC_OUTPUT
