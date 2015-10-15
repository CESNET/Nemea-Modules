/**
 * \file packetreceiver.h
 */

#ifndef PACKETRECEIVER_H
#define PACKETRECEIVER_H

#include <string>
#include "packet.h"

/**
 * \brief Base class for packet receivers.
 */
class PacketReceiver
{
public:
   std::string errmsg; /**< String to store an error messages. */

   /**
    * \brief Get packet from network interface or file.
    * \param [out] packet Variable for storing parsed packet.
    * \return 2 if packet was parsed and stored, 1 if packet was not parsed, 0 if EOF or value < 0 on error
    */
   virtual int get_pkt(Packet &packet) = 0;
};

#endif
