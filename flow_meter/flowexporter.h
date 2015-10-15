/**
 * \file flowexporter.h
 */

#ifndef  FLOWEXPORTER_H
#define FLOWEXPORTER_H

#include "flowifc.h"

/**
 * \brief Base class for flow exporters.
 */
class FlowExporter
{
public:

   /**
    * \brief Send flow record to output interface.
    * \param [in] flow Flow to send.
    * \return 0 on success
    */
   virtual int export_flow(FlowRecord &flow) = 0;
};

#endif
