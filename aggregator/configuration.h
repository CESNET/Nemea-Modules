/*! \file configuration.h
 */
//
// Created by slabimic on 26/02/18.
//


#ifndef AGGREGATOR_CONFIGURATION_H
#define AGGREGATOR_CONFIGURATION_H
/**My Preprocessor Macro.*/
#define DEFAULT_TIMEOUT 10

/**My Preprocessor Macro.*/
#define KEY       0
/**My Preprocessor Macro.*/
#define SUM       1
/**My Preprocessor Macro.*/
#define AVG       2
/**My Preprocessor Macro.*/
#define MIN       3
/**My Preprocessor Macro.*/
#define MAX       4
/**My Preprocessor Macro.*/
#define FIRST     5
/**My Preprocessor Macro.*/
#define LAST      6
/**My Preprocessor Macro.*/
#define BIT_OR    7
/**My Preprocessor Macro.*/
#define BIT_AND   8

/**My Preprocessor Macro.*/
#define TIMEOUT_ACTIVE           0
/**My Preprocessor Macro.*/
#define TIMEOUT_PASSIVE          1
/**My Preprocessor Macro.*/
#define TIMEOUT_GLOBAL           2
/**My Preprocessor Macro.*/
#define TIMEOUT_ACTIVE_PASSIVE   3        // M = Mixed

/**My Preprocessor Macro.*/
#define TIMEOUT_TYPES_COUNT      3        // Count of different timeout types (active_passive dont use new type)

/**My Preprocessor Macro.*/
#define STATIC_FIELDS "TIME_FIRST,TIME_LAST,COUNT"

#include "key.h"
#include "output.h"
/**
 * Class description...
 */
class Config {
private:
   int functions[MAX_KEY_FIELDS];        /*!< Variable brief description. */
   char *field_names[MAX_KEY_FIELDS];    /*!< Variable brief description. */
   int used_fields;                      /*!< Variable brief description. */
   int timeout[TIMEOUT_TYPES_COUNT];     /*!< Variable brief description. */
   int timeout_type;                     /*!< Variable brief description. */
   bool variable_flag;                   /*!< Variable brief description. */
public:
    /**
     *
     */
   Config();
    /**
     *
     */
   ~Config();
    /**
     *
     * @return
     */
   int get_used_fields();
    /**
     *
     * @param index
     * @return
     */
   const char * get_name(int index);
    /**
     *
     * @return
     */
   bool is_variable();
    /**
     *
     * @param flag
     */
   void set_variable(bool flag);
    /**
     *
     * @param index
     * @return
     */
   bool is_key(int index);
    /**
     *
     * @param index
     * @param func_id
     * @return
     */
   bool is_func(int index, int func_id);
    /**
     *
     * @param index
     * @param field_type
     * @return
     */
   agg_func get_function_ptr(int index, ur_field_type_t field_type);
    /**
     *
     * @param index
     * @param field_type
     * @return
     */
   final_avg get_avg_ptr(int index, ur_field_type_t field_type);
    /**
     *
     * @param func
     * @param field_name
     */
   void add_member(int func, const char *field_name);
    /**
     *
     * @param type
     * @return
     */
   int get_timeout(int type);
    /**
     *
     * @return
     */
   char get_timeout_type();
    /**
     *
     * @param input
     */
   void set_timeout(const char *input);
    /**
     *
     * @return
     */
   char * return_template_def();
   /**
    *
    */
   void print();
};

#endif //AGGREGATOR_CONFIGURATION_H