        #                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nemea-modules], [2.26.0], [nemea@cesnet.cz])
AC_CONFIG_SRCDIR([flowcounter/flowcounter.c])
AC_CONFIG_HEADERS([config.h])
RELEASE=1
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
                CFLAGS="-std=gnu11 -Wall -g -O0 $CFLAGS"
                CXXFLAGS="-std=gnu++11 -Wall -g -O0 $CXXFLAGS"
        fi], [CFLAGS="-std=gnu11 -Wall -g -O3 $CFLAGS"
              CXXFLAGS="-std=gnu++11 -Wall -g -O3 $CXXFLAGS"
              CPPFLAGS="-DNDEBUG=1 $CPPFLAGS"])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

AM_PROG_AR
LT_INIT()

pkgdatadir=${datadir}/nemea
PKGDATADIR=$(eval echo $(eval echo ${pkgdatadir}))
AC_SUBST(PKGDATADIR)
AC_SUBST(pkgdatadir)
AC_DEFINE_DIR(PKGDATADIR, [pkgdatadir], [Path to configuration files])
pkgsysconfdir=${sysconfdir}/nemea
AC_SUBST(pkgsysconfdir)
AC_DEFINE_DIR(SYSCONFDIR, [pkgsysconfdir], [Path to configuration files])
AC_DEFINE_DIR(BINDIR, [bindir], [Path to executable files])
AC_SUBST(BINDIR)

bashcompldir=${sysconfdir}/bash_completion.d
AC_SUBST(bashcompldir)

deviceclassifierdatadir=${pkgdatadir}/device_classifier
AC_DEFINE_DIR(DEVICECLASSIFIERDATADIR, [deviceclassifierdatadir], [Path to SVM data files])
AC_SUBST(DEVICECLASSIFIERDATADIR)
AC_SUBST(deviceclassifierdatadir)

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
AC_CHECK_PROG(PYTHON, python3, python3, [""])
AC_SUBST(PYTHON)
# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
AC_CHECK_PROG(DEBUILD, debuild, debuild, [""])
AX_PTHREAD([LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"],
    [AC_MSG_ERROR([pthread not found])])

AC_ARG_ENABLE(repobuild, AS_HELP_STRING([--enable-repobuild],
		[enable local compilation without system installed NEMEA libraries, default: no]),
[case "${enableval}" in
	yes) repobuild=true ;;
	no)  repobuild=false ;;
	*)   AC_MSG_ERROR([bad value ${enableval} for --enable-repobuild]) ;;
esac], [repobuild=false])

AX_C_BIGENDIAN_CROSS

AX_OPENMP([], [AC_MSG_ERROR([OpenMP was not found. Some modules need it (e.g. merger)])])
AC_SUBST(OPENMP_CFLAGS)

backup_libs=${LIBS}
NONNEMEA_LIBS=${backup_libs}
AC_SUBST(NEMEA_FRAMEWORK_LIBS)

AX_LIBTRAP_CHECK
AX_UNIREC_CHECK
AX_NEMEACOMMON_CHECK
NEMEA_FRAMEWORK_LIBS=${LIBS}
AC_SUBST(NEMEA_FRAMEWORK_LIBS)
#LIBS=${backup_libs}

PKG_CHECK_MODULES([cmocka], [cmocka], [have_cmocka="yes"], [have_cmocka="no"])
AM_CONDITIONAL([HAVE_CMOCKA], [test x$have_cmocka = xyes])

AC_ARG_WITH([openssl],
        [AS_HELP_STRING([--without-openssl], [Force to disable openssl])],
        [if test x$withval = xyes; then
        PKG_CHECK_MODULES([openssl], [openssl], [have_openssl="yes"], [have_openssl="no"])
        fi],
        [PKG_CHECK_MODULES([openssl], [openssl], [have_openssl="yes"], [have_openssl="no"])])

AM_CONDITIONAL([HAVE_OPENSSL], [test x$have_openssl = xyes])
if test x$have_openssl = xyes; then
  AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if the openssl is available])
  RPM_REQUIRES+=" openssl"
  RPM_BUILDREQ+=" openssl-devel"
else
  AC_DEFINE([HAVE_OPENSSL], [0], [Define to 1 if the openssl is available])
fi

AC_ARG_WITH([libcurl],
        [AS_HELP_STRING([--without-libcurl], [Force to disable libcurl])],
        [if test x$withval = xyes; then
        PKG_CHECK_MODULES([libcurl], [libcurl], [have_libcurl="yes"], [have_libcurl="no"])
        fi],
        [PKG_CHECK_MODULES([libcurl], [libcurl], [have_libcurl="yes"], [have_libcurl="no"])])

AM_CONDITIONAL([HAVE_LIBCURL], [test x$have_libcurl = xyes])
if test x$have_libcurl = xyes; then
  AC_DEFINE([HAVE_LIBCURL], [1], [Define to 1 if the libcurl is available])
  RPM_REQUIRES+=" libcurl"
  RPM_BUILDREQ+=" libcurl-devel"
else
  AC_DEFINE([HAVE_LIBCURL], [0], [Define to 1 if the libcurl is available])
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
	AC_CHECK_HEADER(libnf.h, AC_CHECK_LIB(nf, lnf_open, [libnf=yes],
	  [AC_MSG_WARN([libnf not found. The nfreader module will not be compiled.])]
	), AC_MSG_WARN([libnf.h not found. The nfreader module will not be compiled.]))
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

AX_PROG_LUA([], [], [
AX_LUA_HEADERS([], [AC_MSG_WARN([lua.h not found. The luamodule module will not be compiled.])])
AX_LUA_LIBS([liblua=yes], AC_MSG_WARN([liblua not found. The luamodule module will not be compiled.]))
], [AC_MSG_WARN([lua not found. The luamodule module will not be compiled.])])

AM_CONDITIONAL(HAVE_LIBLUA, test x${liblua} = xyes)

GTEST_HEADER="googletest/googletest/include/gtest/gtest.h"
AC_MSG_CHECKING(for googletest submodule)
AM_CONDITIONAL([HAVE_GOOGLETEST], [test -f $GTEST_HEADER])
AS_IF([test -f googletest/googletest/include/gtest/gtest.h],
	[AC_DEFINE(HAVE_GOOGLETEST, 1, [Define to 1 if the googletest submodule is available]) AC_MSG_RESULT(yes)],
	[AC_MSG_WARN([
The googletest submodule is not present, so such tests are omitted. To prevent skipping use command:
git clone --recurse-submodules <this_repository> or
git clone https://github.com/google/googletest.git])]
)


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

AM_CONDITIONAL(MAKE_DEB, test x$DEBUILD != x)

#DX_INIT_DOXYGEN([nemea-cpd], [Doxyfile], [doc])

# list of all *.in (and Makefile.am) files to process by configure script
AC_CONFIG_FILES([Makefile
                 aggregator/Makefile
                 anonymizer/Makefile
                 backscatter/Makefile
                 flow_age_stats/Makefile
                 biflow_aggregator/Makefile
                 bloom_history/Makefile
                 debug_sender/Makefile
                 device_classifier/Makefile
                 device_classifier/libsvm/tools/train.sh
                 device_classifier/libsvm/tools/binary.py
                 device_classifier/libsvm/tools/grid.py
                 device_classifier/libsvm/Makefile
                 device_classifier/libsvm/data/Makefile
                 device_classifier/libsvm/tools/Makefile
                 email_reporter/Makefile
                 flowcounter/Makefile
                 flow_meter/Makefile
                 googletest_example/Makefile
                 ipv6stats/Makefile
                 json_dump/Makefile
                 json_replay/Makefile
                 link_traffic/Makefile
                 link_traffic/munin/Makefile
                 link_traffic/link_traff2json.py
                 logger/Makefile
                 logreplay/Makefile
                 merger/Makefile
                 merger/test/Makefile
                 mux/Makefile
                 demux/Makefile
                 natpair/Makefile
                 nemea-modules.spec
                 nfreader/Makefile
                 pdns_exporter/Makefile
                 prefix_tags/Makefile
                 proto_traffic/Makefile
                 proto_traffic/munin/Makefile
                 report2idea/Makefile
                 report2idea/amplificationdetector/Makefile
                 report2idea/bruteforce/Makefile
                 report2idea/dgadetection/Makefile
                 report2idea/ddos/Makefile
                 report2idea/dnstunnel/Makefile
                 report2idea/haddrscan/Makefile
                 report2idea/hoststats/Makefile
                 report2idea/blacklist/Makefile
                 report2idea/minerdetector/Makefile
                 report2idea/sipbruteforce/Makefile
                 report2idea/sshbruteforceml/Makefile
                 report2idea/venom/Makefile
                 report2idea/voipfraud/Makefile
                 report2idea/vportscan/Makefile
                 report2idea/warden_filer/Makefile
                 resolver/Makefile
                 scalar-aggregator/Makefile
                 sni_dataset_saver/Makefile
                 topn/Makefile
                 traffic_repeater/Makefile
                 unirec2json/Makefile
                 unirecfilter/lib/Makefile
                 unirecfilter/lib/liburfilter.pc
                 unirecfilter/Makefile
                 unirecfilter/test/Makefile
                 endiverter/Makefile
                 nfwriter/Makefile
                 luamodule/Makefile
                 luamodule/tests/Makefile
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
echo "trap2man.sh............: $TRAP2MAN"
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
