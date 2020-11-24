#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_GOOGLETEST
#include "gtest/gtest.h"

int main(int argc, char **argv)
{
   // invoking the tests 
   ::testing::InitGoogleTest(&argc, argv);
   return RUN_ALL_TESTS();
}

#else

int main(int argc, char **argv)
{
   // skip this test suite
   return 77;
}
#endif

