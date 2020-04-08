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

static void test_array_ip4(void **state)
{
   int result;
   urfilter_t *urf = urfilter_create("SRC_IP in [10.0.0.1, 172.16.0.2, 192.168.0.1, 192.168.1.1]", "testifc0");
   assert_int_equal(urfilter_compile(urf), URFILTER_TRUE);

   ur_template_t *tmplt = ur_create_template("SRC_IP,DST_PORT", NULL);
   void *rec = ur_create_record(tmplt, 0);
   void *fv = ur_get_ptr_by_id(tmplt, rec, ur_get_id_by_name("SRC_IP"));
   ip_from_str("172.16.0.1", fv);

   result = urfilter_match(urf, tmplt, rec);
   assert_int_equal(result, 0);

   ip_from_str("10.0.0.1", fv);
   result = urfilter_match(urf, tmplt, rec);
   assert_int_equal(result, 1);

   urfilter_destroy(urf);

   ur_free_record(rec);
   ur_free_template(tmplt);
}

static void test_array_double(void **state)
{
   int result;
   urfilter_t *urf = urfilter_create("SCALE in [1.5, 2.7, 3.14]", "testifc0");
   assert_int_equal(urfilter_compile(urf), URFILTER_TRUE);

   ur_template_t *tmplt = ur_create_template("SRC_IP,DST_PORT,SCALE", NULL);
   void *rec = ur_create_record(tmplt, 0);
   double *fv = ur_get_ptr_by_id(tmplt, rec, ur_get_id_by_name("SCALE"));
   *fv = 1.8;

   result = urfilter_match(urf, tmplt, rec);
   assert_int_equal(result, 0);

   *fv = 3.14;
   result = urfilter_match(urf, tmplt, rec);
   assert_int_equal(result, 1);

   urfilter_destroy(urf);

   ur_free_record(rec);
   ur_free_template(tmplt);
}

static void test_array_time(void **state)
{
   int result;
   // TODO - segfault:
   //urfilter_t *urf = urfilter_create("SCALE in [2020-04-09T01:02:21, 2020-04-09T01:02:23, 2020-04-09T01:02:22]", "testifc0");
   //
   urfilter_t *urf = urfilter_create("TIME in [2020-04-09T01:02:21, 2020-04-09T01:02:23, 2020-04-09T01:02:22]", "testifc0");
   assert_int_equal(urfilter_compile(urf), URFILTER_TRUE);

   ur_template_t *tmplt = ur_create_template("SRC_IP,DST_PORT,TIME", NULL);
   void *rec = ur_create_record(tmplt, 0);
   ur_time_t *fv = ur_get_ptr_by_id(tmplt, rec, ur_get_id_by_name("TIME"));
   ur_time_from_string(fv, "2019-04-09T01:02:21");
   result = urfilter_match(urf, tmplt, rec);
   assert_int_equal(result, 0);

   ur_time_from_string(fv, "2020-04-09T01:02:22");
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
   ur_define_field("SCALE", UR_TYPE_DOUBLE);
   ur_define_field("TIME", UR_TYPE_TIME);

   const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_create_destroy),
      cmocka_unit_test(test_checkipandport),
      cmocka_unit_test(test_array),
      cmocka_unit_test(test_array_ip4),
      cmocka_unit_test(test_array_double),
      cmocka_unit_test(test_array_time)
   };
   return cmocka_run_group_tests(tests, NULL, NULL);
}

