# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([lib-user-test],[0.0.0], [example@example.com])
AM_INIT_AUTOMAKE([foreign]) # Does not require NEWS, COPYING, AUTHORS, ChangeLog or README

# silent make https://autotools.io/automake/silent.html
# silent rules enabled by default with 'yes'
# disable silent runles with ./configure --disable-silent-rules
# AM_SILENT_RULES([yes]) # less verbose make output 

AC_CONFIG_SRCDIR([main.c])
#AC_CONFIG_MACRO_DIR([m4])

AC_LANG([C]) # Use C not C++

AC_PROG_CC # check for compiler
AC_PROG_INSTALL
AC_PROG_CC_C_O # Need to have per product flags myexecutable_CFLAG

# Checks for libraries
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([BSL], [bsl >= 2.0.0])

AC_HEADER_ASSERT # ./configure --disable-assert to define NDEBUG 

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
