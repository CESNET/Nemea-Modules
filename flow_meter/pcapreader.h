/**
 * \file pcapreader.h
 */

#ifndef PCAPREADER_H
#define PCAPREADER_H

#include <pcap/pcap.h>

#include "flow_meter.h"
#include "packet.h"
#include "packetreceiver.h"

/**
 * \brief Class for reading packets from file or network interface.
 */
class PcapReader : public PacketReceiver
{
public:
   PcapReader();
   PcapReader(const options_t &options);
   ~PcapReader();

   int open_file(const std::string &file);
   int init_interface(const std::string &interface);
   void close();
   int get_pkt(Packet &packet);
private:
   pcap_t *handle; /**< pcap file handler */
};

void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data);

#endif
