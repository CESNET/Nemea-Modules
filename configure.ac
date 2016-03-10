#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nemea-modules], [2.1.0], [traffic-analysis@cesnet.cz])
AC_CONFIG_SRCDIR([flowcounter/flowcounter.c])
AC_CONFIG_HEADERS([config.h])
RELEASE=2
AC_SUBST(RELEASE)
USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`
AC_SUBST(USERNAME)
AC_SUBST(USERMAIL)
AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects])
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIR([m4])
# Must be checked before default -g -O2 is set:
AC_ARG_ENABLE([debug],
        AC_HELP_STRING([--enable-debug],
        [Enable build with debug symbols and without optimizations.]),
        [if test "$enableval" = "yes"; then
                CFLAGS="-Wall -g -O0 $CFLAGS"
                CXXFLAGS="-Wall -g -O0 $CXXFLAGS"
        fi], [CFLAGS="-Wall -O3 $CFLAGS"
              CXXFLAGS="-Wall -O3 $CXXFLAGS"
              CPPFLAGS="-DNDEBUG=1 $CPPFLAGS"])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

LT_INIT()

pkgdatadir=${datadir}/nemea
PKGDATADIR=$(eval echo $(eval echo ${pkgdatadir}))
AC_SUBST(PKGDATADIR)
AC_SUBST(pkgdatadir)
AC_DEFINE_DIR(PKGDATADIR, [pkgdatadir], [Path to configuration files])
AC_DEFINE_DIR(SYSCONFDIR, [sysconfdir], [Path to configuration files])
RPM_REQUIRES=
RPM_BUILDREQ=

# Checks for programs.
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CHECK_PROG(PYTHON, python, python, [""])
AC_SUBST(PYTHON)
# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
AX_PTHREAD([LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"],
    [AC_MSG_ERROR([pthread not found])])

AC_ARG_ENABLE(repobuild, AS_HELP_STRING([--disable-repobuild],
		[disable local compilation without system installed Nemea libraries, default: yes]),
[case "${enableval}" in
	yes) repobuild=true ;;
	no)  repobuild=false ;;
	*)   AC_MSG_ERROR([bad value ${enableval} for --enable-repobuild]) ;;
esac], [repobuild=true])

AX_OPENMP([], [AC_MSG_ERROR([OpenMP was not found. Some modules need it (e.g. logger and merger)])])
AC_SUBST(OPENMP_CFLAGS)

AX_LIBTRAP_CHECK
AX_UNIREC_CHECK
AX_NEMEACOMMON_CHECK

AC_CHECK_HEADER(idna.h,
         AC_CHECK_LIB(idn, stringprep_check_version, [libidn=yes], AC_MSG_WARN([libidn not found. The ipdetect module from blacklistfilter will not be compiled.])), AC_MSG_WARN([libidn.h not found. Blacklistfilter modules will not be compiled.]))

AM_CONDITIONAL(HAVE_LIBIDN, test x${libidn} = xyes)
if [[ -z "$HAVE_LIBIDN_TRUE" ]]; then
RPM_REQUIRES+=" libidn"
RPM_BUILDREQ+=" libidn-devel"
fi

AC_ARG_WITH([nfreader],
	AC_HELP_STRING([--without-nfreader], [Skip nfreader module.]),
        [if test "$withval" = "no"; then
                withnfreader="no"
        else
                withnfreader="yes"
        fi], [withnfreader="yes"])

if test x${withnfreader} = xyes; then
	# Checks for libraries.
	AC_CHECK_LIB(nf, lnf_open, [libnf=yes],
	  [AC_CHECK_LIB(nfdump, nfdump_init, [libnfdump=yes],
	    [AC_MSG_WARN([libnf and libnfdump not found. The nfreader module will not be compiled.])]
	  )]
	)

fi
AM_CONDITIONAL(HAVE_LIBNFDUMP, test x${libnfdump} = xyes && test x${withnfreader} = xyes)
if [[ -z "$HAVE_LIBNFDUMP_TRUE" ]]; then
RPM_REQUIRES+=" libnfdump"
RPM_BUILDREQ+=" libnfdump-devel"
fi

AM_CONDITIONAL(HAVE_LIBNF, test x${libnf} = xyes && test x${withnfreader} = xyes)
if [[ -z "$HAVE_LIBNF_TRUE" ]]; then
RPM_REQUIRES+=" libnf"
RPM_BUILDREQ+=" libnf-devel"
fi

AC_CHECK_PROG(BISON, bison, yes, [""])
AC_CHECK_PROG(FLEX, flex, yes, [""])

AM_CONDITIONAL(HAVE_BISON, test xyes = x${BISON} -a xyes = x${FLEX})
if [[ -z "$HAVE_BISON_TRUE" ]]; then
RPM_BUILDREQ+=" bison"
RPM_BUILDREQ+=" flex"
fi

AC_CHECK_HEADER(pcap.h,
        AC_CHECK_LIB(pcap, pcap_open_live, [libpcap=yes], AC_MSG_WARN([libpcap not found. The flow_meter module will not be compiled.])), AC_MSG_WARN([pcap.h not found. The flow_meter module will not be compiled.]))

AM_CONDITIONAL(HAVE_LIBPCAP, test x${libpcap} = xyes)
if [[ -z "$HAVE_LIBPCAP_TRUE" ]]; then
RPM_REQUIRES+=" libpcap"
RPM_BUILDREQ+=" libpcap-devel"
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h locale.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h omp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([alarm clock_gettime floor gettimeofday localeconv memset mkdir pow setlocale sqrt strchr strdup strerror strstr strtol strtoul])

# Check for sigaction
AC_CHECK_FUNC(sigaction, AC_DEFINE(HAVE_SIGACTION, 1, [Define if you have the 'sigaction' function]))

#RPM & Doxygen
AC_SUBST(RPMBUILD)
if test -z "$RPMBUILD"; then
	AC_MSG_WARN([Due to missing rpmbuild you will not able to generate RPM package.])
fi

RPM_RELEASE=1
AC_SUBST(RPM_RELEASE)
AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

#DX_INIT_DOXYGEN([nemea-cpd], [Doxyfile], [doc])

# list of all *.in (and Makefile.am) files to process by configure script
AC_CONFIG_FILES([Makefile
                 anonymizer/Makefile
                 debug_sender/Makefile
                 email_reporter/Makefile
                 flowcounter/Makefile
                 flow_meter/Makefile
                 json_dump/Makefile
                 json_replay/Makefile
                 logger/Makefile
                 logreplay/Makefile
                 merger/Makefile
                 nemea-modules.spec
                 nfreader/Makefile
                 report2idea/Makefile
                 traffic_repeater/Makefile
                 unirecfilter/Makefile
               ])

AC_SUBST(RPM_REQUIRES)
AC_SUBST(RPM_BUILDREQ)
AC_OUTPUT

echo
echo
echo "------------------------------------------------------------------------"
echo "$PACKAGE $VERSION"
echo "------------------------------------------------------------------------"
echo
echo
echo "Configuration Options Summary:"
echo
echo "  ASM.(32 bit only)..: $ASM"
echo "  Static binary......: $static"
echo
echo "Documentation..........: ${build_doc}"
echo
echo "UniRec processor.......: $UNIRECPROC"
echo "Compilation............: make (or gmake)"
echo "  CPPFLAGS.............: $CPPFLAGS"
echo "  CFLAGS...............: $CFLAGS"
echo "  CXXFLAGS.............: $CXXFLAGS"
echo "  LDFLAGS..............: $LDFLAGS"
echo "  LIBS.................: $LIBS"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo

