#ifndef __BLOOM_HISTORY_H_
#define __BLOOM_HISTORY_H_
#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>


static const int INTERFACE_IN = 0;

UR_FIELDS (
   ipaddr DST_IP,
   uint32 PREFIX_TAG
)

#ifndef DEBUG
#define DEBUG 0
#endif
#define debug_print(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)


#endif // __BLOOM_HISTORY_H_
