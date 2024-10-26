AC_INIT([ifdnlnfc], [0.1])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_MACRO_DIR([m4])
AM_PROG_AR
AC_PROG_CC
LT_INIT([disable-static],[enable-shared])
AC_CONFIG_SRCDIR([src/ifdnlnfc.c])
AC_CONFIG_FILES([Makefile src/Makefile])
PKG_CHECK_MODULES([LIBNL], [libnl-3.0])
PKG_CHECK_MODULES([LIBNL_GENL], [libnl-genl-3.0])
PKG_CHECK_MODULES([PCSC], [libpcsclite])
AC_CHECK_HEADERS([linux/nfc.h])
AC_CHECK_DECL(NFC_ATTR_TARGET_ATS,,CFLAGS+=" -Iinclude",[[#include <linux/nfc.h>]])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
