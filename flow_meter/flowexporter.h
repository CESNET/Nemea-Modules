#ifndef  FLOWEXPORTER_H
#define FLOWEXPORTER_H

#include "flowifc.h"

//Base class FlowExporter
class FlowExporter
{
public:
   virtual int export_flow(FlowRecord &flow) = 0;
};

#endif
