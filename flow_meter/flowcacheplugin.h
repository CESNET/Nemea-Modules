/**
 * \file flowcacheplugin.h
 */

#ifndef FLOWCACHEPLUGIN_H
#define FLOWCACHEPLUGIN_H

#include <string>

#include "packet.h"
#include "flowifc.h"

#define FLOW_FLUSH (0x1 << 0)

using namespace std;

/**
 * \brief Class template for flow cache plugins.
 */
class FlowCachePlugin
{
public:

   /**
    * \brief Virtual destructor.
    */
   virtual ~FlowCachePlugin()
   {
   }

   /**
    * \brief Called before the start of processing.
    */
   virtual void init()
   {
   }

   /**
    * \brief Called after a new flow record is created.
    * \param [in,out] rec Reference to flow record.
    * \param [in] pkt Parsed packet.
    * \return 0 on success or FLOW_FLUSH option.
    */
   virtual int post_create(FlowRecord &rec, const Packet &pkt)
   {
      return 0;
   }

   /**
    * \brief Called before an existing record is update.
    * \param [in,out] rec Reference to flow record.
    * \param [in,out] pkt Parsed packet.
    * \return 0 on success or FLOW_FLUSH option.
    */
   virtual int pre_update(FlowRecord &rec, Packet &pkt)
   {
      return 0;
   }

   /**
    * \brief Called after an existing record is updated.
    * \param [in,out] rec Reference to flow record.
    * \param [in,out] pkt Parsed packet.
    */
   virtual void post_update(FlowRecord &rec, const Packet &pkt)
   {
   }

   /**
    * \brief Called before a flow record is exported from the cache.
    * \param [in,out] rec Reference to flow record.
    */
   virtual void pre_export(FlowRecord &rec)
   {
   }

   /**
    * \brief Called when everything is processed.
    */
   virtual void finish()
   {
   }

   /**
    * \brief Get unirec template string from plugin.
    * \return Unirec template string.
    */
   virtual std::string get_unirec_field_string()
   {
      return "";
   }
};

#endif
