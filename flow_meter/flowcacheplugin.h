#ifndef FLOWCACHEPLUGIN_H
#define FLOWCACHEPLUGIN_H

#include "packet.h"
#include "flowifc.h"

#define FLOW_FLUSH (0x1 << 0)

class FlowCachePlugin
{
public:
   virtual ~FlowCachePlugin()
   {
   }

   // Called before the start of processing
   virtual void init()
   {
   }
   // Called after a new flow record is created
   virtual int post_create(FlowRecord &rec, const Packet &pkt)
   {
      return 0;
   }
   // Called before an existing record is updated
   virtual int pre_update(FlowRecord &rec, Packet &pkt)
   {
      return 0;
   }
   // Called after an existing record is updated
   virtual void post_update(FlowRecord &rec, const Packet &pkt)
   {
   }
   // Called before a flow record is exported from the cache
   virtual void pre_export(FlowRecord &rec)
   {
   }
   // Called when everything is processed
   virtual void finish()
   {
   }

};

#endif
