#ifndef FLOWRECORD_H
#define FLOWRECORD_H

/* Interface between flow cache and flow exporter. */

#include <stdint.h>
#include <stdlib.h>

// Values of field presence indicator flags (flowFieldIndicator)
// (Names of the fields are inspired by IPFIX specification)
#define FLW_FLOWFIELDINDICATOR       (0x1 << 0)
#define FLW_HASH                     (0x1 << 1)
#define FLW_FLOWSTARTTIMESTAMP       (0x1 << 2)
#define FLW_FLOWENDTIMESTAMP         (0x1 << 3)
#define FLW_IPVERSION                (0x1 << 4)
#define FLW_PROTOCOLIDENTIFIER       (0x1 << 5)
#define FLW_IPCLASSOFSERVICE         (0x1 << 6)
#define FLW_IPTTL                    (0x1 << 7)
#define FLW_SOURCEIPV4ADDRESS        (0x1 << 8)
#define FLW_DESTINATIONIPV4ADDRESS   (0x1 << 9)
#define FLW_SOURCEIPV6ADDRESS        (0x1 << 10)
#define FLW_DESTINATIONIPV6ADDRESS   (0x1 << 11)
#define FLW_SOURCETRANSPORTPORT      (0x1 << 12)
#define FLW_DESTINATIONTRANSPORTPORT (0x1 << 13)
#define FLW_PACKETTOTALCOUNT         (0x1 << 14)
#define FLW_OCTETTOTALLENGTH         (0x1 << 15)
#define FLW_TCPCONTROLBITS           (0x1 << 16)

// Some common sets of flags
#define FLW_IPV4_MASK (\
   FLW_IPVERSION | \
   FLW_PROTOCOLIDENTIFIER | \
   FLW_IPCLASSOFSERVICE | \
   FLW_IPTTL | \
   FLW_SOURCEIPV4ADDRESS | \
   FLW_DESTINATIONIPV4ADDRESS \
)

#define FLW_IPV6_MASK (\
   FLW_IPVERSION | \
   FLW_PROTOCOLIDENTIFIER | \
   FLW_IPCLASSOFSERVICE | \
   FLW_SOURCEIPV6ADDRESS | \
   FLW_DESTINATIONIPV6ADDRESS \
)

#define FLW_TCP_MASK (\
   FLW_SOURCETRANSPORTPORT | \
   FLW_DESTINATIONTRANSPORTPORT | \
   FLW_TCPCONTROLBITS \
)

#define FLW_UDP_MASK (\
   FLW_SOURCETRANSPORTPORT | \
   FLW_DESTINATIONTRANSPORTPORT \
)

#define FLW_IPSTAT_MASK (\
   FLW_PACKETTOTALCOUNT | \
   FLW_OCTETTOTALLENGTH \
)

#define FLW_TIMESTAMPS_MASK (\
   FLW_FLOWSTARTTIMESTAMP | \
   FLW_FLOWENDTIMESTAMP \
)

#define FLW_PAYLOAD_MASK (\
   FLW_FLOWPAYLOADSTART | \
   FLW_FLOWPAYLOADSIZE \
)

enum extTypeEnum {
   http_request = 0,
   http_response
};

// Flow record extenstion base class (derived class should add their own fields)
struct FlowRecordExt {
   FlowRecordExt *next;
   uint16_t extType; // Type of extension (given by some enum)

   // Constructor
   FlowRecordExt(uint16_t type) : next(NULL), extType(type)
   {
   }
   // Virutal destructor, needed if some fields in derived classes are dynamically allocated
   virtual ~FlowRecordExt()
   {
      if (next != NULL) {
         delete next;
      }
   }
};

struct FlowRecord {
   uint64_t flowFieldIndicator;
   double   flowStartTimestamp;
   double   flowEndTimestamp;
   uint8_t  ipVersion;
   uint8_t  protocolIdentifier;
   uint8_t  ipClassOfService;
   uint8_t  ipTtl;
   uint32_t sourceIPv4Address;
   uint32_t destinationIPv4Address;
   char     sourceIPv6Address[16];
   char     destinationIPv6Address[16];
   uint16_t sourceTransportPort;
   uint16_t destinationTransportPort;
   uint32_t packetTotalCount;
   uint64_t octetTotalLength;
   uint8_t  tcpControlBits;
   FlowRecordExt *exts; // List of extestions

   void addExtension(FlowRecordExt* ext)
   {
      if (exts == NULL) {
         // first extenstion - just set the new one
         exts = ext;
         exts->next = NULL;
      } else {
         // there already are some extensions - find the last one and append the new one after it
         FlowRecordExt *ext_ptr = exts;
         while (ext_ptr->next != NULL) {
            ext_ptr = ext_ptr->next;
         }
         ext_ptr->next = ext;
         ext_ptr->next->next = NULL;
      }
   }

   FlowRecordExt *getExtension(uint16_t extType)
   {
      FlowRecordExt *ext_ptr = exts;
      while (ext_ptr != NULL) {
         if (ext_ptr->extType == extType) {
            return ext_ptr;
         }
         ext_ptr = ext_ptr->next;
      }
      return NULL;
   }

   void removeExtensions()
   {
      if (exts != NULL) {
         delete exts;
         exts = NULL;
      }
   }

   FlowRecord() : exts(NULL)
   {
   }

   ~FlowRecord()
   {
      removeExtensions();
   }
};

enum httpMethodEnum {
   GET = 0,
   HEAD,
   POST,
   PUT,
   DELETE,
   TRACE,
   OPTIONS,
   CONNECT,
   PATCH,
   UNDEFINED
};

struct FlowRecordExtHTTPReq : FlowRecordExt {
   httpMethodEnum httpReqMethod;
   char httpReqHost[64];
   char httpReqUrl[128];
   char httpReqUserAgent[128];
   char httpReqReferer[128];

   FlowRecordExtHTTPReq() : FlowRecordExt(http_request)
   {
      httpReqHost[0] = 0;
      httpReqUrl[0] = 0;
      httpReqUserAgent[0] = 0;
      httpReqReferer[0] = 0;
   }
};

struct FlowRecordExtHTTPResp : FlowRecordExt {
   uint16_t httpRespCode;
   char httpRespContentType[32];

   FlowRecordExtHTTPResp() : FlowRecordExt(http_response)
   {
      httpRespCode = 0;
      httpRespContentType[0] = 0;
   }
};


//Base class FlowExporter
class FlowExporter
{
public:
   virtual int export_flow(FlowRecord &flow) = 0;
};

#endif
