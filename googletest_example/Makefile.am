if HAVE_GOOGLETEST
gtest_cppflags=-I$(top_srcdir)/googletest/googletest/include -I$(top_srcdir)/googletest/googletest
gtest_ldflags=-pthread
gtest_ldadd=libgtest.la

check_LTLIBRARIES = libgtest.la
libgtest_la_SOURCES = $(top_srcdir)/googletest/googletest/src/gtest-all.cc
libgtest_la_CPPFLAGS = $(gtest_cppflags) -pthread
else
gtest_cppflags=
gtest_ldflags=
gtest_ldadd=
endif

check_PROGRAMS = test_suite_example1
test_suite_example1_SOURCES = main.cpp \
		test_suite_example1.cpp sum.cpp
test_suite_example1_LDADD = $(gtest_ldadd)
test_suite_example1_LDFLAGS = $(gtest_ldflags)
test_suite_example1_CPPFLAGS = $(gtest_cppflags)

# Notice the +=
check_PROGRAMS += test_suite_example2
test_suite_example2_SOURCES = main.cpp \
		test_suite_example2.cpp sub.cpp
test_suite_example2_LDADD = $(gtest_ldadd)
test_suite_example2_LDFLAGS = $(gtest_ldflags)
test_suite_example2_CPPFLAGS = $(gtest_cppflags)

TESTS = $(check_PROGRAMS)
include ../aminclude.am
