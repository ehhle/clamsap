# init
AC_INIT(clamsap, 0.103.3, markus.strehle@sap.com)

# put configure auxiliary into config
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_HEADERS(config.h)
# AC_CONFIG_SRCDIR(src/vsclam.c)
# AC_CONFIG_SRCDIR(src/vsclamd.c)

AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM

# Automake initialization
AM_INIT_AUTOMAKE(clamsap, 0.103.3)

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_LIBTOOL
# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(clamav.h stdlib.h string.h)
have_clamav=no
AC_CHECK_HEADER(clamav.h, have_clamav=yes)
if test "$have_clamav" = "no"; then
	AC_MSG_ERROR(Missing clamav.h! Install ClamAV package)
fi

dnl change this on a release
dnl VERSION="devel-`date +%Y%m%d`"
VERSION="0.103.3"
AC_DEFINE_UNQUOTED([VERSION],"$VERSION",[Version number of package])

LC_CURRENT=9
LC_REVISION=9
LC_AGE=2
CLAMSAP_VERSION_INFO="$LC_CURRENT":"$LC_REVISION":"$LC_AGE"
AC_SUBST(CLAMSAP_VERSION_INFO)
AC_SUBST(VERSION)
AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LIBEXT)

LIBEXT=.so
case "$target_os" in
*linux-gnu)
     build_os="linux"
     LIBEXT=.so
     ;;
freebsd*)
     build_os="linux"
     LIBEXT=.so
     ;;
openbsd*)
     build_os="linux"
     LIBEXT=.so
     ;;
netbsd*)
     build_os="linux"
     LIBEXT=.so
     ;;
*solaris*)
     build_os="solaris" 
     LIBEXT=.so
     ;;
darwin*)
     build_os="darwin" 
     LIBEXT=.so
     ;;
cygwin*)
     build_os="mingw" 
     LIBEXT=.dll
     ;;
mingw*)
     build_os="mingw" 
     LIBEXT=.dll
     ;;
esac

# conditional stuff
AM_CONDITIONAL(LINUX, test "$build_os" = "linux")
AM_CONDITIONAL(DARWIN, test "$build_os" = "darwin")
AM_CONDITIONAL(SOLARIS, test "$build_os" = "solaris")
AM_CONDITIONAL(WINDOWS, test "$build_os" = "mingw")


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_STAT
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getcwd memset setlocale socket strchr strdup strrchr strstr])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT

AC_MSG_RESULT(

=============
Information
=============


Run now 'make' and find the library in 'src/.libs'
Load the library [lib]clam[d]sap with option -V into SAP processes


)
