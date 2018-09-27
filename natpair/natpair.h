/**
 * \file natpair.h
 * \brief Module for pairing flows which undergone Network address translation (NAT) process.
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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <iostream>
#include <cstdlib>

using namespace std;

#define VERBOSE(...) if (verbose >= 0) { \
   printf(__VA_ARGS__); \
}

#define UNIREC_INPUT_TEMPLATE "DST_IP,SRC_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST"                              ///< UniRec input template.
#define UNIREC_OUTPUT_TEMPLATE "LAN_IP,RTR_IP,WAN_IP,LAN_PORT,RTR_PORT,WAN_PORT,TIME_FIRST,TIME_LAST,PROTOCOL,DIRECTION"   ///< UniRec output template.

#define THREAD_CNT 2    ///< Number of threads for handling input interfaces. LAN and WAN.

#define IP_P_1_START 167772160   ///< 10.0.0.0
#define IP_P_1_END   184549375   ///< 10.255.255.255
#define IP_P_2_START 2886729728  ///< 172.16.0.0
#define IP_P_2_END   2887778303  ///< 172.31.255.255
#define IP_P_3_START 3232235520  ///< 192.168.0.0
#define IP_P_3_END   3232301055  ///< 192.168.255.255

#define DEFAULT_CHECK_TIME 600000   ///< Frequency with which the flowcache is cleared of old data (10 minutes).
#define DEFAULT_FREE_TIME  5000     ///< Maximum time for which unpaired flows can remain in flow cache (5 minutes).
#define DEFAULT_CACHE_SIZE 2000     ///< Number of elements in the flow cache which triggers cache cleaning.

/**
 * \brief Holds possible directions of network flows.
 */
enum nat_direction_t {
   LANtoWAN = 0,  ///< The network flow travels from LAN to WAN.
   WANtoLAN,      ///< The network flow travels from WAN to LAN.
   NONE           ///< The flow probably did not undergone the NAT process (communication inside LAN).
};

/**
 * \brief Holds possible input interfaces.
 */
enum net_scope_t {
   LAN = 0,    ///< LAN input interface.
   WAN         ///< WAN input interface.
};

/**
 * \brief Class containing all necessary information about the network flow which undergone the NAT process.
 */
class Flow {
public:
   /**
    * \brief Basic constructor.
    */
   Flow();

   /**
    * \brief Basic copy constructor.
    *
    * \param[in] other  Flow object to be deep copied.
    */
   Flow(const Flow &other);

   /**
    * \brief Basic assign operator.
    *
    * \param[in] other  Flow object to be deep copied.
    */
   Flow& operator=(const Flow &other);

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
   bool operator==(const Flow &other) const;

   /**
    * \brief Partially fill the Flow object with data contained inside a network flow received from a libtrap input interface.
    *
    * \param[in] tmplt  UniRec input template.
    * \param[in] rec    UniRec input record.
    * \param[in] sc     Parameter indicating whether the network flow was captured in LAN or WAN.
    *
    * \return True if the flow object was filled, false on error (IPv6, the flow did not undergone the NAT process).
    */
   bool prepare(const ur_template_t *tmplt, const void *rec, net_scope_t sc);

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
   uint64_t hashKey() const;

   /**
    * \brief Fill the data of a flow observed in LAN resp. WAN
    *        with the data of a flow observed in WAN resp. LAN.
    *
    * \param[in] other  Flow object which can be paired to this object.
    */
   void complete(const Flow &other);

   /**
    * \brief Get time of the flow appearance.
    *
    * \return Time of the flow appearance.
    */
   ur_time_t getTime() const;

   /**
    * \brief Send complete Flow object via the libtrap output interface.
    *
    * \param[in] tmplt  UniRec output template.
    * \param[in] rec    UniRec output record.
    *
    * \return TRAP_E_OK on success, error otherwise
    */
   int sendToOutput(const ur_template_t *tmplt, void *rec) const;

   /**
    * \brief Convert the Flow object to a textual representation.
    *
    * \param[in,out] str Output stream where should be the Flow object written.
    * \param[in]     f   Flow object which is to be converted to the textual representation.
    *
    * \return The input stream containing textual representation of the Flow object at the end.
    */
   friend ostream& operator<<(ostream& str, const Flow &f);
private:
   /**
    * \brief Set direction of the flow based on source and destination IP address of the flow.
    *
    * \param[in] src_ip    Source IP address of the flow.
    * \param[in] dst_ip    Destination IP address of the flow.
    */
   void setDirection(uint32_t src_ip, uint32_t dst_ip);

   /**
    * \brief Fill the object data based on the direction of the network flow (LAN->WAN or WAN->LAN).
    *
    * \param[in] src_ip    Source IP address of the network flow.
    * \param[in] dst_ip    Destination IP address of the network flow.
    * \param[in] src_port  Source port of the network flow.
    * \param[in] dst_port  Destination port of the network flow.
    */
   void adjustDirection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);

   uint32_t lan_ip;           ///< IPv4 address of the device in LAN.
   uint32_t wan_ip;           ///< IPv4 address of the device in WAN.
   uint16_t lan_port;         ///< Port used on the device in LAN.
   uint16_t router_port;      ///< Port used on the router which performs NAT (WAN interface).
   uint16_t wan_port;         ///< Port used on the device in WAN.
   ur_time_t lan_time_first;  ///< Time when the communication was first observed in LAN.
   ur_time_t lan_time_last;   ///< Time when the communication was last observed in LAN.
   ur_time_t wan_time_first;  ///< Time when the communication was first observed in WAN.
   ur_time_t wan_time_last;   ///< Time when the communication was last observed in WAN.
   uint8_t protocol;          ///< Protocol used (TCP / UDP).
   uint8_t direction;         ///< Direction of the network flow (LAN->WAN, WAN->LAN).
   net_scope_t scope;         ///< Scope specifies on which interface was the network flow first seen.
};
