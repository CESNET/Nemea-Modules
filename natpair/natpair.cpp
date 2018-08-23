/**
 * \file natpair.cpp
 * \brief Module for pairing flows which undergone the Network address translation (NAT) process.
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \date 2017 - 2018
 */
/*
 * Copyright (C) 2017 - 2018 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <semaphore.h>
#include <ctime>
#include <queue>
#include <unordered_map>
#include "natpair.h"
#include "fields.h"

UR_FIELDS (
   ipaddr DST_IP,    ///< destination IP address of the network flow
   ipaddr SRC_IP,    ///< source IP address of the network flow
   uint16 DST_PORT,  ///< destination port of the network flow
   uint16 SRC_PORT,  ///< source port of the network flow
   ipaddr LAN_IP,    ///< IP address of the client in LAN
   ipaddr RTR_IP,    ///< IP address of the WAN interface of the router performing NAT process
   ipaddr WAN_IP,    ///< IP address of the host in WAN
   uint16 LAN_PORT,  ///< port of the client in LAN
   uint16 RTR_PORT,  ///< port on the WAN interface of the router performing NAT process
   uint16 WAN_PORT,  ///< port of the host in LAN
   time TIME_FIRST,  ///< time of the first packet in the flow
   time TIME_LAST,   ///< time of the last packet in the flow
   uint8 PROTOCOL,   ///< protocol used (TCP, UDP...)
   uint8 DIRECTION   ///< 0 stands for LAN to WAN, 1 stands for WAN to LAN
)

trap_module_info_t *module_info = NULL;      ///< Module info for libtrap.
queue<Flow> q;                               ///< Shared queue which contains partially filled Flow objects.
static int stop = 0;                         ///< Indicates whether the module should stop.
pthread_t th[THREAD_CNT];                    ///< Array of PIDs of threads handling input interfaces.
pthread_mutex_t q_mut;                       ///< Mutex used for locking the shared queue.
pthread_mutex_t l_mut;                       ///< Mutex used for locking UniRec parts during initialization and finalization.
sem_t q_empty;                               ///< Semaphore indicating whether the shared queue contains any objects which need processing.
uint64_t g_check_time = DEFAULT_CHECK_TIME;  ///< Frequency of flow cache cleaning.
uint64_t g_free_time = DEFAULT_FREE_TIME;    ///< Maximum time for which unpaired flows can remain in flow cache.
uint32_t g_cache_size = DEFAULT_CACHE_SIZE;  ///< Number of elements in the flow cache which triggers cache cleaning.
uint32_t g_router_ip;                        ///< IP address of the WAN interface of the router performing NAT process.
uint8_t th_alive = THREAD_CNT;               ///< Number of alive threads.

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("NATpair module", "This module receives flows from LAN and WAN probes and pairs flows which undergone the Network address translation (NAT) process.", 2, 1)

#define MODULE_PARAMS(PARAM) \
   PARAM('c', "checktime", "Frequency of flow cache cleaning. [sec] (default: 600s)", required_argument, "uint32") \
   PARAM('f', "freetime", "Maximum time for which unpaired flows can remain in flow cache. [sec] (default: 5s)", required_argument, "uint32") \
   PARAM('r', "router", "IPv4 address of WAN interface of the router which performs the NAT process.", required_argument, "string") \
   PARAM('s', "size", "Number of elements in the flow cache which triggers chache cleaning. (default: 2000)", required_argument, "uint32")

/**
 * \brief Check whether the passed IPv4 address is private.
 *
 * \param[in] ip  IPv4 address that should be checked.
 *
 * \return True if the IPv4 address is private, false otherwise.
 */
bool is_ip_priv(uint32_t ip) {
   return ((ip >= IP_P_1_START && ip <= IP_P_1_END) || (ip >= IP_P_2_START && ip <= IP_P_2_END) || (ip >= IP_P_3_START && ip <= IP_P_3_END));
}


/**
 * \brief Basic constructor.
 */
Flow::Flow() : lan_ip(0), wan_ip(0), lan_port(0), router_port(0), wan_port(0), lan_time_first(0), 
               lan_time_last(0), wan_time_first(0), wan_time_last(0), protocol(0), direction(0), scope(LAN) {}

/**
 * \brief Basic copy constructor.
 *
 * \param[in] other  Flow object to be deep copied.
 */
Flow::Flow(const Flow &other)
{
   lan_ip = other.lan_ip;
   wan_ip = other.wan_ip;
   lan_port = other.lan_port;
   router_port = other.router_port;
   wan_port = other.wan_port;
   lan_time_first = other.lan_time_first;
   lan_time_last = other.lan_time_last;
   wan_time_first = other.wan_time_first;
   wan_time_last = other.wan_time_last;
   protocol = other.protocol;
   direction = other.direction;
   scope = other.scope;
}

/**
 * \brief Basic assign operator.
 *
 * \param[in] other  Flow object to be deep copied.
 */
Flow& Flow::operator=(const Flow &other)
{
   lan_ip = other.lan_ip;
   wan_ip = other.wan_ip;
   lan_port = other.lan_port;
   router_port = other.router_port;
   wan_port = other.wan_port;
   lan_time_first = other.lan_time_first;
   lan_time_last = other.lan_time_last;
   wan_time_first = other.wan_time_first;
   wan_time_last = other.wan_time_last;
   protocol = other.protocol;
   direction = other.direction;
   scope = other.scope;   
   return *this; 
}

/**
 * \brief Compare whether two flows can be paired.
 *
 * Two flows can be paired, if the following conditions are met:
 *    - One flow is from LAN and the other from WAN
 *    - IP address of the device in WAN is equal in both flows
 *    - port on the device in WAN is equal in both flows
 *    - protocol is equal in both flows
 *    - the direction of the both flows in equal (LAN->WAN or WAN->LAN)
 *    - the time stamp of appearance of both flows is almost the same
 *
 * \param[in] other  Flow object to be compared.
 *
 * \return True if the flows can be paired, false otherwise.
 */
bool Flow::operator==(const Flow &other) const
{
   if (scope == WAN - other.scope && wan_ip == other.wan_ip && wan_port == other.wan_port && protocol == other.protocol && direction == other.direction) {
      ur_time_t t_lan_first;
      ur_time_t t_lan_last;
      ur_time_t t_wan_first;
      ur_time_t t_wan_last;
      if (scope == LAN) {
         t_lan_first = lan_time_first;
         t_lan_last = lan_time_last;
         t_wan_first = other.wan_time_first;
         t_wan_last = other.wan_time_last;
      } else {
         t_lan_first = other.lan_time_first;
         t_lan_last = other.lan_time_last;
         t_wan_first = wan_time_first;
         t_wan_last = wan_time_last;
      }

      if ((direction == LANtoWAN && t_lan_first <= t_wan_first && t_lan_last <= t_wan_last) || (direction == WANtoLAN && t_lan_first >= t_wan_first && t_lan_last >= t_wan_last)) {
         return (ur_timediff(t_lan_first, t_wan_first) < 2 && ur_timediff(t_lan_last, t_wan_last) < 3);
      }

      return false;
   }

   return false;
}

/**
 * \brief Get time of the flow appearance.
 *
 * \return Time of the flow appearance.
 */
ur_time_t Flow::getTime() const
{
   return ((scope == LAN) ? lan_time_last : wan_time_last);
}

/**
 * \brief Fill the data of a flow observed in LAN resp. WAN
 *        with the data of a flow observed in WAN resp. LAN.
 *
 * \param[in] other  Flow object which can be paired to this object.
 */
void Flow::complete(const Flow &other)
{
   if (scope == LAN) {
      router_port = other.router_port;
      wan_time_first = other.wan_time_first;
      wan_time_last = other.wan_time_last;
   } else {
      lan_ip = other.lan_ip;
      lan_port = other.lan_port;
      lan_time_first = other.lan_time_first;
      lan_time_last = other.lan_time_last;
   }
}

/**
 * \brief Set direction of the flow based on source and destination IP address of the flow.
 *
 * \param[in] src_ip    Source IP address of the flow.
 * \param[in] dst_ip    Destination IP address of the flow.
 */
void Flow::setDirection(uint32_t src_ip, uint32_t dst_ip)
{
   direction = NONE;

   if ((is_ip_priv(src_ip) && !is_ip_priv(dst_ip)) || (src_ip == g_router_ip)) {
      direction = LANtoWAN;
   } else if ((!is_ip_priv(src_ip) && is_ip_priv(dst_ip)) || (dst_ip == g_router_ip)) {
      direction = WANtoLAN;
   }
}

/**
 * \brief Generate key which can be used to identify similar flows.
 *
 * Flows are considered similar if the following conditions are met:
 *    - IP address of the device in WAN in both flows is the same
 *    - port used on the device in WAN in both flows is the same
 *    - protocol used in both flows is the same
 *    - direction of both flows is the same
 *
 * \return Key which can be used to identify all similar flows.
 */
uint64_t Flow::hashKey() const
{
   uint64_t key;

   ((uint32_t *)&key)[0] = wan_ip;
   ((uint16_t *)&key)[2] = wan_port;
   ((uint8_t *)&key)[6] = protocol;
   ((uint8_t *)&key)[7] = direction;

   return key;
}

/**
 * \brief Fill the object data based on the direction of the network flow (LAN->WAN or WAN->LAN).
 *
 * \param[in] src_ip    Source IP address of the network flow.
 * \param[in] dst_ip    Destination IP address of the network flow.
 * \param[in] src_port  Source port of the network flow.
 * \param[in] dst_port  Destination port of the network flow.
 */
void Flow::adjustDirection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
   if (direction == WANtoLAN) {
      swap(src_ip, dst_ip);
      swap(src_port, dst_port);
   }

   wan_ip = dst_ip;
   wan_port = dst_port;
   if (scope == LAN) {
      lan_ip = src_ip;
      lan_port = src_port;
   } else {
      router_port = src_port;
   }
}

/**
 * \brief Partially fill the Flow object with data contained inside a network flow received from a libtrap input interface.
 *
 * \param[in] tmplt  UniRec input template.
 * \param[in] rec    UniRec input record.
 * \param[in] sc     Parameter indicating whether the network flow was captured in LAN or WAN.
 *
 * \return True if the flow object was filled, false on error (IPv6, the flow did not undergone the NAT process).
 */
bool Flow::prepare(const ur_template_t *tmplt, const void *rec, net_scope_t sc)
{
   ip_addr_t *ip_src = &ur_get(tmplt, rec, F_SRC_IP);
   ip_addr_t *ip_dst = &ur_get(tmplt, rec, F_DST_IP);
   if (ip_is6(ip_src) || ip_is6(ip_dst)) {
      return false;
   }

   scope = sc;
   protocol = ur_get(tmplt, rec, F_PROTOCOL);
   ((sc == LAN) ? lan_time_first : wan_time_first) = ur_get(tmplt, rec, F_TIME_FIRST);
   ((sc == LAN) ? lan_time_last : wan_time_last) = ur_get(tmplt, rec, F_TIME_LAST);
   uint32_t src_ip = ip_get_v4_as_int(ip_src);
   uint32_t dst_ip = ip_get_v4_as_int(ip_dst);
   uint16_t src_port = ur_get(tmplt, rec, F_SRC_PORT);
   uint16_t dst_port = ur_get(tmplt, rec, F_DST_PORT);
   setDirection(src_ip, dst_ip);
   if (direction == NONE) {
      return false;
   }

   adjustDirection(src_ip, dst_ip, src_port, dst_port);
   return true;
}

/**
 * \brief Send complete Flow object via the libtrap output interface.
 *
 * \param[in] tmplt  UniRec output template.
 * \param[in] rec    UniRec output record.
 *
 * \return TRAP_E_OK on success, error otherwise
 */
int Flow::sendToOutput(const ur_template_t *tmplt, void *rec) const
{
   ur_set(tmplt, rec, F_LAN_IP, ip_from_int(lan_ip));
   ur_set(tmplt, rec, F_RTR_IP, ip_from_int(g_router_ip));
   ur_set(tmplt, rec, F_WAN_IP, ip_from_int(wan_ip));
   ur_set(tmplt, rec, F_LAN_PORT, lan_port);
   ur_set(tmplt, rec, F_RTR_PORT, router_port);
   ur_set(tmplt, rec, F_WAN_PORT, wan_port);

   if (direction == LANtoWAN) {
      ur_set(tmplt, rec, F_TIME_FIRST, lan_time_first);
      ur_set(tmplt, rec, F_TIME_LAST, wan_time_last);
   } else {
      ur_set(tmplt, rec, F_TIME_FIRST, wan_time_first);
      ur_set(tmplt, rec, F_TIME_LAST, lan_time_last);
   }

   ur_set(tmplt, rec, F_PROTOCOL, protocol);
   ur_set(tmplt, rec, F_DIRECTION, direction);

   return trap_send(0, rec, ur_rec_fixlen_size(tmplt)); 
}

/**
 * \brief Convert the Flow object to a textual representation.
 *
 * \param[in,out] str Output stream where should be the Flow object written.
 * \param[in]     f   Flow object which is to be converted to the textual representation.
 *
 * \return The input stream containing textual representation of the Flow object at the end.
 */
ostream& operator<<(ostream& str, const Flow &f)
{
   char buf[64];
   time_t sec;
   int msec;
   ip_addr_t tmp;
   
   sec = ur_time_get_sec(f.lan_time_first);
   msec = ur_time_get_msec(f.lan_time_first);
   strftime(buf, 63, "%FT%T", gmtime(&sec));

   str << "[" << buf << "." << msec << " - ";

   sec = ur_time_get_sec(f.lan_time_last);
   msec = ur_time_get_msec(f.lan_time_last);
   strftime(buf, 63, "%FT%T", gmtime(&sec));

   str << buf << "." << msec << "]\t";

   tmp = ip_from_int(f.lan_ip);
   ip_to_str(&tmp, buf);

   str << buf << ":" << f.lan_port;;
   str << ((f.direction == LANtoWAN) ? "\t->\t" : "\t<-\t");

   tmp = ip_from_int(g_router_ip);
   ip_to_str(&tmp, buf);

   str << buf << ":" << f.router_port;
   str << ((f.direction == LANtoWAN) ? "\t->\t" : "\t<-\t");

   tmp = ip_from_int(f.wan_ip);
   ip_to_str(&tmp, buf);

   str << buf << ":" << f.wan_port << '\t';

   sec = ur_time_get_sec(f.wan_time_first);
   msec = ur_time_get_msec(f.wan_time_first);
   strftime(buf, 63, "%FT%T", gmtime(&sec));

   str << "[" << buf << "." << msec << " - ";

   sec = ur_time_get_sec(f.wan_time_last);
   msec = ur_time_get_msec(f.wan_time_last);
   strftime(buf, 63, "%FT%T", gmtime(&sec));

   str << buf << "." << msec << "]\t";

   return str;
}

/**
 * \brief Main function for processing network flows from input interfaces.
 *
 * \param[in] arg Pointer to a net_scope_t structure indicating interface from which the network flows should be read (LAN or WAN).
 *
 * \return NULL.
 */

void* process_incoming_data(void *arg)
{
   /* Convert passed argument to net_scope_t enum. */
   net_scope_t scope = ((uint64_t)arg == 0) ? LAN : WAN;

   /*
      Lock the creation of UniRec template.

      ******************* IMPORTANT *******************
      To whomever who is reading this: if UniRec is by any chance finally thread safe,
      consider yourself lucky to rewrite this function without unnecessary locks.
   */
   pthread_mutex_lock(&l_mut);
   ur_template_t *tmplt = ur_create_input_template((int)scope, UNIREC_INPUT_TEMPLATE, NULL);
   if (!tmplt){
      fprintf(stderr, "Error: Input template %d could not be created.\n", scope);
      sem_post(&q_empty);
      pthread_mutex_unlock(&l_mut);
      return NULL;
   }

   pthread_mutex_unlock(&l_mut);

   /*
      Basically just expanded TRAP_RECEIVE macro, but with added locks,
      since UniRec was not thread safe at the time of creation of this module.
      Sorry...
   */
   while (!stop) {
      const void *data;
      uint16_t data_size;
      int ret = trap_ctx_recv(trap_get_global_ctx(), (int) scope, &data, &data_size);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         const char *spec = NULL;
         uint8_t data_fmt;
         if (trap_ctx_get_data_fmt(trap_get_global_ctx(), TRAPIFC_INPUT, (int) scope, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "Data format was not loaded.\n");
            return NULL;
         } else {
            pthread_mutex_lock(&l_mut);
            tmplt = ur_define_fields_and_update_template(spec, tmplt);
            if (tmplt == NULL) {
               fprintf(stderr, "Template could not be edited.\n");
               pthread_mutex_unlock(&l_mut);
               return NULL;
            } else {
               if (tmplt->direction == UR_TMPLT_DIRECTION_BI) {
                  char *spec_cpy = ur_cpy_string(spec);
                  if (spec_cpy == NULL) {
                     fprintf(stderr, "Memory allocation problem.\n");
                     ur_free_template(tmplt);
                     pthread_mutex_unlock(&l_mut);
                     return NULL;
                  } else {
                     trap_ctx_set_data_fmt(trap_get_global_ctx(), tmplt->ifc_out, TRAP_FMT_UNIREC, spec_cpy);
                  }
               }
            }

            pthread_mutex_unlock(&l_mut);
         }
      }

      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      if (data_size < ur_rec_fixlen_size(tmplt)) {
         if (data_size <= 1) {
            break;
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(tmplt), data_size);
            break;
         }
      }

      /* Attempt to create a partial Flow object from the received network flow. */
      Flow f;
      if (f.prepare(tmplt, data, scope)) {
         /* Insert the partial Flow object to  the shared queue. */
         pthread_mutex_lock(&q_mut);
         q.push(f);
         pthread_mutex_unlock(&q_mut);
         /* Signal the main thread that it has work that needs to be done. */
         sem_post(&q_empty);
      }
   }

   /* Decrease the number of ongoing threads. The last thread increases the semaphore, resulting in shutting down the main thread. */
   pthread_mutex_lock(&q_mut);
   if (--th_alive == 0) {
      pthread_mutex_unlock(&q_mut);
      sem_post(&q_empty);
   } else {
      pthread_mutex_unlock(&q_mut);
   }

   /* Lock deletion of UniRec template. */
   pthread_mutex_lock(&l_mut);
   ur_free_template(tmplt);
   pthread_mutex_unlock(&l_mut);
   return NULL;
}

int main(int argc, char **argv)
{
   int ret;
   signed char opt;
   ip_addr_t tmp;

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'c':
         if (sscanf(optarg, "%" SCNu64 "", &g_check_time) != 1 || g_check_time == 0) {
            fprintf(stderr, "Error: Invalid value of argument -c.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            TRAP_DEFAULT_FINALIZATION();
            return -1;
         }

         g_check_time *= 1000;
         break;
      case 'f':
         if (sscanf(optarg, "%" SCNu64 "", &g_free_time) != 1 || g_free_time == 0) {
            fprintf(stderr, "Error: Invalid value of argument -f.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            TRAP_DEFAULT_FINALIZATION();
            return -1;
         }

         g_free_time *= 1000;
         break;
      case 'r':
         if (ip_from_str(optarg, &tmp) != 1 || ip_is6(&tmp)) {
            fprintf(stderr, "Error: Invalid value of IPv4 address of WAN interface of the router handling NAT.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            TRAP_DEFAULT_FINALIZATION();
            return -1;
         }

         g_router_ip = ip_get_v4_as_int(&tmp);
         break;
      case 's':
         if (sscanf(optarg, "%" SCNu32 "", &g_cache_size) != 1 || g_cache_size == 0) {
            fprintf(stderr, "Error: Invalid value of argument -s.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            TRAP_DEFAULT_FINALIZATION();
            return -1;
         }

         break;
      default:
         fprintf(stderr, "Error: Invalid arguments.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         TRAP_DEFAULT_FINALIZATION();
         return -1;
      }
   }

   if (g_router_ip == 0) {
      fprintf(stderr, "Error: Value of IPv4 address of WAN interface of the router must be specified.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }

   pthread_attr_t attr;
   pthread_attr_init(&attr);
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
   pthread_mutex_init(&q_mut, NULL);
   pthread_mutex_init(&l_mut, NULL);
   sem_init(&q_empty, 0, 0);
   ur_template_t *tmplt = NULL;
   void *out_rec = NULL;
   unordered_map<uint64_t, vector<Flow> > flowcache;
   ur_time_t t_now = 0, t_last = 0;

   /* Create separate threads for receiving network flows from input interfaces. */
   for (uint64_t i = 0; i < THREAD_CNT; i++) {
      if (pthread_create(&th[i], &attr, process_incoming_data, (void *)i) != 0) {
         fprintf(stderr, "Error: Unable to start data-receiving thread.\n");
         pthread_attr_destroy(&attr);
         goto cleanup;
      }
   }

   pthread_attr_destroy(&attr);

   /* Lock the creation of UniRec template and record creation. */
   pthread_mutex_lock(&l_mut);
   tmplt = ur_create_output_template(0, UNIREC_OUTPUT_TEMPLATE, NULL);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Output template could not be created.\n");
      pthread_mutex_unlock(&l_mut);
      goto cleanup;
   }

   out_rec = ur_create_record(tmplt, 0);
   if (out_rec == NULL) {
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      pthread_mutex_unlock(&l_mut);
      goto cleanup;
   }

   pthread_mutex_unlock(&l_mut);

   /* Main cycle responsible for pairing partial Flow objects, sending them to the output interface, or printing them. */
   while (true) {
      Flow f;

      /* Wait until the is a Flow object in the shared queue. */
      sem_wait(&q_empty);
      pthread_mutex_lock(&q_mut);
      if (!q.empty()) {
         /* Take the Flow object. */
         f = q.front();
         q.pop();
      } else {
         pthread_mutex_unlock(&q_mut);
         break;
      }

      pthread_mutex_unlock(&q_mut);

      /* Generate key of the partial Flow object which can be used to find similar partial Flow objects. */
      uint64_t key = f.hashKey();
      auto it = flowcache.find(key);

      /* No similar Flow object found yet in the flowcache -> create vector for Flow objects with the same key and insert this object. */
      if (it == flowcache.end()) {
         flowcache.insert(make_pair<uint64_t&, vector<Flow> >(key, vector<Flow>(1,f)));
         continue;
      }

      /*
         Some similar (with same key) partial Flow objects were found.
         Iterate through them and attempt to pair this partial Flow object to another previously inserted Flow object.
      */
      bool matched = false;
      for (auto v = it->second.begin(); v != it->second.end(); ++v) {
         if ((*v) == f) {
            matched = true;
            t_now = f.getTime();

            /* Complete one of the partial Flow objects with the information from the second. */
            f.complete(*v);

            /* Erase the stored object from the vector, or erase the whole vector, if it has only 1 object. */
            if (it->second.size() == 1) {
               flowcache.erase(it);
            } else {
               it->second.erase(v);
            }

            /* Send the complete Flow object to the output interface. */
            ret = f.sendToOutput(tmplt, out_rec);
            if (ret != TRAP_E_OK) {
               fprintf(stderr, "ERROR: Unable to send data to output interface: %s.\n", trap_last_error_msg);
            }

            TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, break, break);
            //cout << f << endl;
            break;
         }
      }

      /* Insert the Flow object at the end of the vector in case it was not matched to any other Flow object with same key. */
      if (!matched) {
         it->second.push_back(f);
      }

      /* Attempt to clear the flowcache of old partial Flow objects which were never paired for some reason. */
      if (flowcache.size() > g_cache_size || (t_now >= t_last && ur_timediff(t_now, t_last) >= g_check_time)) {
         unordered_map<uint64_t, vector<Flow> > newcache;
         for (auto it = flowcache.begin(); it != flowcache.end(); ++it) {
            vector<Flow> newvec;
            uint64_t key = it->first;
            for (auto v = it->second.begin(); v != it->second.end(); ++v) {
               ur_time_t t_flow = v->getTime();
               if (t_flow >= t_now || (t_flow < t_now && ur_timediff(t_flow, t_now) < g_free_time)) {
                  newvec.push_back((*v));
               }
            }

            if (newvec.size() > 0) {
               newcache.insert(make_pair<uint64_t&, vector<Flow> >(key, vector<Flow>(newvec)));
            }
         }

         t_last = t_now;
         flowcache = newcache;
      }
   }

cleanup:
   for (int i = 0; i < THREAD_CNT; i++ ) {
      pthread_join(th[i], NULL);      
   }

   pthread_mutex_destroy(&q_mut);
   pthread_mutex_destroy(&l_mut);
   sem_destroy(&q_empty);
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   if (out_rec) {
      ur_free_record(out_rec);   
   }
   
   if (tmplt) {
      ur_free_template(tmplt);   
   }
   
   ur_finalize();
   return 0;
}

