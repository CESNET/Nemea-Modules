#ifndef PCAPREADER_H
#define PCAPREADER_H

#include <pcap/pcap.h>

#include "flow_meter.h"
#include "packet.h"
#include "packetreceiver.h"

class PcapReader : public PacketReceiver
{
public:
   PcapReader();
   PcapReader(options_t &options);
   ~PcapReader();

   int open_file(const std::string &file);
   int init_interface(const std::string &interface);
   void close();
   int get_pkt(Packet &packet);
   //int cnt_parsed, cnt_total;
private:
   pcap_t *handle;
};

void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data);

#endif
