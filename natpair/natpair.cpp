/**
 * \file natpair.cpp
 * \brief Module for pairing flows which undergone the Network address translation (NAT) process.
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2017 CESNET
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
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   ipaddr LAN_IP,    // IP address of the client in LAN
   ipaddr RTR_IP,    // IP address of the WAN interface of the router performing NAT proccess
   ipaddr WAN_IP,    // IP address of the host in WAN
   uint16 LAN_PORT,  // port of the client in LAN
   uint16 RTR_PORT,  // port on the WAN interface of the router performing NAT proccess
   uint16 WAN_PORT,  // port of the host in LAN
   time TIME_FIRST,  // time of the first packet in the flow
   time TIME_LAST,   // time of the last packet in the flow
   uint8 PROTOCOL,   // protocol used (TCP, UDP...)
   uint8 DIRECTION   // 0 stands for LAN to WAN, 1 stands for WAN to LAN
)

trap_module_info_t *module_info = NULL;
queue<Flow> q;
static int stop = 0;
pthread_t th[THREAD_CNT];
pthread_mutex_t q_mut,l_mut;
sem_t q_empty;
uint64_t g_check_time = DEFAULT_CHECK_TIME;
uint64_t g_free_time = DEFAULT_FREE_TIME;
uint32_t g_cache_size = DEFAULT_CACHE_SIZE;
uint32_t g_router_ip;
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("NATpair module", "This module receives flows from LAN and WAN probes and pairs flows which undergone the Network address translation (NAT) process.", 2, 1)

#define MODULE_PARAMS(PARAM) \
   PARAM('c', "checktime", "Frequency of flow cache cleaning. [sec] (default: 600s)", required_argument, "uint32") \
   PARAM('f', "freetime", "Maximum time for which unpaired flows can remain in flow cache. [sec] (default: 5s)", required_argument, "uint32") \
   PARAM('r', "router", "IPv4 address of WAN interface of the router which performs the NAT process.", required_argument, "string") \
   PARAM('s', "size", "Number of elements in the flow cache which triggers chache cleaning. (default: 2000)", required_argument, "uint32")

bool is_ip_priv(uint32_t ip) {
   return ((ip >= IP_P_1_START && ip <= IP_P_1_END) || (ip >= IP_P_2_START && ip <= IP_P_2_END) || (ip >= IP_P_3_START && ip <= IP_P_3_END));
}

Flow::Flow() : lan_ip(0), wan_ip(0), lan_port(0), router_port(0), wan_port(0), lan_time_first(0), 
               lan_time_last(0), wan_time_first(0), wan_time_last(0), protocol(0), direction(0), scope(LAN) {}

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

ur_time_t Flow::getTime() const
{
   return ((scope == LAN) ? lan_time_last : wan_time_last);
}

net_scope_t Flow::getScope() const
{
   return scope;
}

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

void Flow::setDirection(uint32_t src_ip, uint32_t dst_ip)
{
   direction = NONE;

   if ((is_ip_priv(src_ip) && !is_ip_priv(dst_ip)) || (src_ip == g_router_ip)) {
      direction = LANtoWAN;
   } else if ((!is_ip_priv(src_ip) && is_ip_priv(dst_ip)) || (dst_ip == g_router_ip)) {
      direction = WANtoLAN;
   }
}

uint64_t Flow::hashKey() const
{
   uint64_t key;

   ((uint32_t *)&key)[0] = wan_ip;
   ((uint16_t *)&key)[2] = wan_port;
   ((uint8_t *)&key)[6] = protocol;
   ((uint8_t *)&key)[7] = direction;

   return key;
}

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

ostream& operator<<(ostream& str, const Flow &other)
{
   char buf[32];
   time_t sec;
   int msec;
   ip_addr_t tmp;
   
   sec = ur_time_get_sec(other.lan_time_first);
   msec = ur_time_get_msec(other.lan_time_first);
   strftime(buf, 31, "%FT%T", gmtime(&sec));

   str << "[" << buf << "." << msec << " - ";

   sec = ur_time_get_sec(other.lan_time_last);
   msec = ur_time_get_msec(other.lan_time_last);
   strftime(buf, 31, "%FT%T", gmtime(&sec));

   str << buf << "." << msec << "]\t";

   tmp = ip_from_int(other.lan_ip);
   ip_to_str(&tmp, buf);

   str << buf << ":" << other.lan_port;;
   str << ((other.direction == LANtoWAN) ? "\t->\t" : "\t<-\t");

   tmp = ip_from_int(g_router_ip);
   ip_to_str(&tmp, buf);

   str << buf << ":" << other.router_port;
   str << ((other.direction == LANtoWAN) ? "\t->\t" : "\t<-\t");

   tmp = ip_from_int(other.wan_ip);
   ip_to_str(&tmp, buf);

   str << buf << ":" << other.wan_port << '\t';

   sec = ur_time_get_sec(other.wan_time_first);
   msec = ur_time_get_msec(other.wan_time_first);
   strftime(buf, 31, "%FT%T", gmtime(&sec));

   str << "[" << buf << "." << msec << " - ";

   sec = ur_time_get_sec(other.wan_time_last);
   msec = ur_time_get_msec(other.wan_time_last);
   strftime(buf, 31, "%FT%T", gmtime(&sec));

   str << buf << "." << msec << "]\t";

   return str;
}

void* process_incoming_data(void *arg)
{
   net_scope_t scope = ((uint64_t)arg == 0) ? LAN : WAN;

   pthread_mutex_lock(&l_mut);
   ur_template_t *tmplt = ur_create_input_template((int)scope, UNIREC_INPUT_TEMPLATE, NULL);
   if (!tmplt){
      fprintf(stderr, "Error: Input template %d could not be created.\n", scope);
      sem_post(&q_empty);
      pthread_mutex_unlock(&l_mut);
      return NULL;
   }
   pthread_mutex_unlock(&l_mut);

   while (!stop) {
      const void *data;
      uint16_t data_size;
      int ret = trap_ctx_recv(trap_get_global_ctx(), (int) scope, &data, &data_size);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         const char *spec = NULL;
         uint8_t data_fmt;
         if (trap_ctx_get_data_fmt(trap_get_global_ctx(), TRAPIFC_INPUT, (int) scope, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "Data format was not loaded.\n");
         } else {
            pthread_mutex_lock(&l_mut);
            tmplt = ur_define_fields_and_update_template(spec, tmplt);
            if (tmplt == NULL) {
               fprintf(stderr, "Template could not be edited.\n");
            } else {
               if (tmplt->direction == UR_TMPLT_DIRECTION_BI) {
                  char *spec_cpy = ur_cpy_string(spec);
                  if (spec_cpy == NULL) {
                     fprintf(stderr, "Memory allocation problem.\n");
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

      Flow f;
      if (f.prepare(tmplt, data, scope)) {
         pthread_mutex_lock(&q_mut);
         q.push(f);
         pthread_mutex_unlock(&q_mut);
         sem_post(&q_empty);
      }
   }

   sem_post(&q_empty);

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
         if (sscanf(optarg, "%" SCNu64 "", &g_check_time) != 1 || g_free_time == 0) {
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

   for (uint64_t i = 0; i < THREAD_CNT; i++) {
      if (pthread_create(&th[i], &attr, process_incoming_data, (void *)i) != 0) {
         fprintf(stderr, "Error: Unable to start data-receiving thread.\n");
         pthread_attr_destroy(&attr);
         goto cleanup;
      }
   }

   pthread_attr_destroy(&attr);

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

   while (true) {
      Flow f;

      sem_wait(&q_empty);
      pthread_mutex_lock(&q_mut);
      if (!q.empty()) {
         f = q.front();
         q.pop();
      } else {
         pthread_mutex_unlock(&q_mut);
         break;
      }

      pthread_mutex_unlock(&q_mut);

      uint64_t key = f.hashKey();
      auto it = flowcache.find(key);
      if (it == flowcache.end()) {
         flowcache.insert(make_pair<uint64_t&, vector<Flow> >(key, vector<Flow>(1,f)));
         continue;
      }

      bool matched = false;
      for (auto v = it->second.begin(); v != it->second.end(); ++v) {
         if ((*v) == f) {
            matched = true;
            t_now = f.getTime();
            f.complete(*v);
            if (it->second.size() == 1) {
               flowcache.erase(it);
            } else {
               it->second.erase(v);
            }

            ret = f.sendToOutput(tmplt, out_rec);
            TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
            //cout << f << endl;
            break;
         }
      }

      if (!matched) {
         it->second.push_back(f);
      }

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

