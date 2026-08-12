# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([lib-user-test],[0.0.0],[example@example.com])
AC_CONFIG_AUX_DIR([build-aux])
#AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign]) # Does not require NEWS, COPYING, AUTHORS, ChangeLog or README
AM_SILENT_RULES([yes]) # less verbose make output

AC_CONFIG_SRCDIR([main.c])

AC_LANG([C]) # Use C not C++

AC_PROG_CC # check for compiler
AX_CHECK_COMPILE_FLAG([-std=c99], [CFLAGS="$CFLAGS -std=c99"])
AC_PROG_INSTALL
AC_PROG_CC_C_O # Need to have per target flags

AC_HEADER_ASSERT # ./configure --disable-assert to define NDEBUG

# Checks for libraries
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([BSL], [bsl]) # should depend on specific version

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
