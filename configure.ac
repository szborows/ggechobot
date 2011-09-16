#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([smlocalui], [0.1], [zborowsk_s_ext@gigaset.com])
AM_INIT_AUTOMAKE([foreign -Wall])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

CPPFLAGS="$CPPFLAGS"
CXXFLAGS="$CXXFLAGS"
CFLAGS="$CFLAGS"
LIBS="$LIBS -lssl -pthread"

# Checks for header files.


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.

AC_CONFIG_FILES([Makefile Doxyfile])
AC_OUTPUT
