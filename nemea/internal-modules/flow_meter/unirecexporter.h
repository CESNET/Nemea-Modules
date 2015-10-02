#ifndef FLOWWRITER_H
#define FLOWWRITER_H

#include <string>
#include <fstream>
#include <map>

#include "flow_meter.h"
#include "flowifc.h"
#include "flowexporter.h"

class UnirecExporter : public FlowExporter
{
   std::string outfileprefix;
   uint32_t flowlinesize;

   std::ostream *flowos;
   std::ostream *dataos;

   std::filebuf flowoutputfile;
   std::filebuf dataoutputfile;

   bool flowfile_opened;
   bool datafile_opened;
   bool dataos_needed;

   void printinfo();

   ur_template_t *tmplt;
   void *data;

public:
   UnirecExporter(const options_t &options)
   {
      this->outfileprefix = options.outfilename;
      this->flowlinesize = options.flowlinesize;

      this->flowfile_opened = false;
      this->datafile_opened = false;
      this->dataos_needed = false;
   }

   int init();
   int close();
   int export_flow(FlowRecord &flow);
};

#endif
