#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_GOOGLETEST

#include "gtest/gtest.h"
#include "my_func.hpp"

using namespace My_sub;

TEST(SubTest, basicUsage)
{
    ASSERT_EQ(sub(4, 2), 2);
}

#endif
