/**
 * \file flowcache.h
 */

#ifndef FLOWCACHE_H
#define FLOWCACHE_H

#include "packet.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "flowexporter.h"

#include <vector>
#include <cstring>

/**
 * \brief Base class for flow caches.
 */
class FlowCache
{
protected:
   FlowExporter *exporter; /**< Instance of FlowExporter used to export flows. */
private:
   std::vector<FlowCachePlugin*> plugins; /**< Array of plugins. */

public:
   /**
    * \brief Put packet into the cache (i.e. update corresponding flow record or create a new one)
    * \param [in] pkt Input parsed packet.
    * \return 0 on success.
    */
   virtual int put_pkt(Packet &pkt) = 0;

   /**
    * \brief Initialize flow cache.
    * Should be called before first call of recv_pkt, after all plugins are added.
    */
   virtual void init()
   {
      plugins_init();
   }

   /**
    * \brief Cleanup function.
    * Should be called after last call of recv_pkt.
    */
   virtual void finish()
   {
      plugins_finish();
   }

   /**
    * \brief Set an instance of FlowExporter used to export flows.
    */
   void set_exporter(FlowExporter *exp)
   {
      exporter = exp;
   }

   /**
    * \brief Add plugin to internal list of plugins.
    * Plugins are always called in the same order, as they were added.
    */
   void add_plugin(FlowCachePlugin *plugin)
   {
      plugins.push_back(plugin);
   }

protected:
   //Every FlowCache implementation should call these functions at appropriate places

   /**
    * \brief Initialize added plugins.
    */
   void plugins_init()
   {
      for (unsigned int i = 0; i < plugins.size(); i++) {
         plugins[i]->init();
      }
   }

   /**
    * \brief Call post_create function for each added plugin.
    * \param [in,out] rec Stored flow record.
    * \param [in] pkt Input parsed packet.
    * \return Options for flow cache.
    */
   int plugins_post_create(FlowRecord &rec, const Packet &pkt)
   {
      int retval = 0;
      for (unsigned int i = 0; i < plugins.size(); i++) {
         int tmp = plugins[i]->post_create(rec, pkt);
         if (tmp != 0) {
            retval = tmp;
         }
      }
      return retval;
   }

   /**
    * \brief Call pre_update function for each added plugin.
    * \param [in,out] rec Stored flow record.
    * \param [in] pkt Input parsed packet.
    * \return Options for flow cache.
    */
   int plugins_pre_update(FlowRecord &rec, Packet &pkt)
   {
      int retval = 0;
      for (unsigned int i = 0; i < plugins.size(); i++) {
         int tmp = plugins[i]->pre_update(rec, pkt);
         if (tmp != 0) {
            retval = tmp;
         }
      }
      return retval;
   }

   /**
    * \brief Call post_update function for each added plugin.
    * \param [in,out] rec Stored flow record.
    * \param [in] pkt Input parsed packet.
    */
   void plugins_post_update(FlowRecord &rec, const Packet &pkt)
   {
      for (unsigned int i = 0; i < plugins.size(); i++) {
         plugins[i]->post_update(rec, pkt);
      }
   }

   /**
    * \brief Call pre_export function for each added plugin.
    * \param [in,out] rec Stored flow record.
    */
   void plugins_pre_export(FlowRecord &rec)
   {
      for (unsigned int i = 0; i < plugins.size(); i++) {
         plugins[i]->pre_export(rec);
      }
   }

   /**
    * \brief Call finish function for each added plugin.
    */
   void plugins_finish()
   {
      for (unsigned int i = 0; i < plugins.size(); i++) {
         plugins[i]->finish();
      }
   }
};

#endif
