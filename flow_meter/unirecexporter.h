/**
 * \file unirecexporter.h
 */

#ifndef UNIREC_EXPORTER_H
#define UNIREC_EXPORTER_H

#include <string>
#include <vector>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "flowcacheplugin.h"
#include "flowexporter.h"

using namespace std;

/**
 * \brief Class for exporting flow records.
 */
class UnirecExporter : public FlowExporter
{
public:
   UnirecExporter();
   int init(const std::vector<FlowCachePlugin *> &plugins);
   void close();
   int export_flow(FlowRecord &flow);

private:
   std::string generate_ext_template(const std::vector<FlowCachePlugin *> &plugins) const;

   ur_template_t *tmplt; /**< Pointer to unirec template. */
   void *record;         /**< Pointer to unirec record. */
};

#endif
