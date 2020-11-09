#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_GOOGLETEST

#include "gtest/gtest.h"
#include "my_func.hpp"

using namespace My_sum;

TEST(SumTest, basicUsage)
{
    ASSERT_EQ(sum(1, 2), 3);
}

#endif
