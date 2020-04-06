#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <unirec/unirec.h>

#include "liburfilter.h"

static void test_create_destroy(void **state)
{
   urfilter_t *urf = urfilter_create("", "testifc0");
   assert_int_equal(urfilter_compile(urf), URFILTER_ERROR);
   urfilter_destroy(urf);

   urfilter_destroy(NULL);
}

static void test_checkipandport(void **state)
{
   urfilter_t *urf = urfilter_create("SRC_IP == \"10.0.0.1\" and DST_PORT==80", "testifc0");
   assert_int_equal(urfilter_compile(urf), URFILTER_TRUE);
   urfilter_destroy(urf);
}

static void test_array(void **state)
{
   urfilter_t *urf = urfilter_create("DST_PORT in [8443, 80, 8080, 443]", "testifc0");
   assert_int_equal(urfilter_compile(urf), URFILTER_TRUE);
   
   ur_template_t *tmplt = ur_create_template("SRC_IP,DST_PORT", NULL);
   void *rec = ur_create_record(tmplt, 0);
   void *fv = ur_get_ptr_by_id(tmplt, rec, ur_get_id_by_name("DST_PORT"));
   *((uint16_t *) fv) = 123;

   int result;
   result = urfilter_match(urf, tmplt, rec);
   assert_int_equal(result, 0);

   *((uint16_t *) fv) = 443;
   result = urfilter_match(urf, tmplt, rec);
   assert_int_equal(result, 1);

   urfilter_destroy(urf);

   ur_free_record(rec);
   ur_free_template(tmplt);
}

int main(void)
{
   ur_define_field("SRC_IP", UR_TYPE_IP);
   ur_define_field("DST_PORT", UR_TYPE_UINT16);

   const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_create_destroy),
      cmocka_unit_test(test_checkipandport),
      cmocka_unit_test(test_array)
   };

   return cmocka_run_group_tests(tests, NULL, NULL);
}

