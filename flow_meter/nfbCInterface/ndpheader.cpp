#include "ndpheader.h"

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pcap_pkthdr ndp_to_pcap_hdr(struct ndp_packet *ndp_packet, struct ndp_header *ndp_header) {
	struct pcap_pkthdr pcap_hdr;
	pcap_hdr.len = pcap_hdr.caplen = ndp_packet->data_length;
	pcap_hdr.ts.tv_sec = ndp_header->timestamp_sec;
	pcap_hdr.ts.tv_usec = ndp_header->timestamp_nsec*1000;
	return pcap_hdr;
}

#ifdef __cplusplus
}
#endif
