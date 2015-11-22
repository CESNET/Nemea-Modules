/**
 * \file unirecexporter.h
 * \brief Flow exporter converting flows to UniRec and sending them to TRAP ifc
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2014-2015 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
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
