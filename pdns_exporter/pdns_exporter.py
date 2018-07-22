#!/usr/bin/python
#
# Copyright (C) 2018 CESNET
#
# LICENSE TERMS
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name of the Company nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# ALTERNATIVELY, provided that this notice is retained in full, this
# product may be distributed under the terms of the GNU General Public
# License (GPL) version 2 or later, in which case the provisions
# of the GPL apply INSTEAD OF those given above.
#
# This software is provided ``as is'', and any express or implied
# warranties, including, but not limited to, the implied warranties of
# merchantability and fitness for a particular purpose are disclaimed.
# In no event shall the company or contributors be liable for any
# direct, indirect, incidental, special, exemplary, or consequential
# damages (including, but not limited to, procurement of substitute
# goods or services; loss of use, data, or profits; or business
# interruption) however caused and on any theory of liability, whether
# in contract, strict liability, or tort (including negligence or
# otherwise) arising in any way out of the use of this software, even
# if advised of the possibility of such damage.

import sys
import pytrap
import argparse
import json
import gzip
import socket
from datetime import datetime

"""
This module reads flow data from TRAP interface and export flow data to JSON and
store JSON to files on disk. Data in JSON are in format to process in Passive DNS.
"""

def store_json(json_data):
    file_name = "pdns_data_" + datetime.now().strftime("%Y%m%d.%H%M%S") + ".json.gz"
    with gzip.open(file_name, "wb") as output_file:
        output_file.write(json.dumps(json_data, sort_keys=False).encode('utf-8'))

parser = argparse.ArgumentParser(description='Module for exporting flow data to format for Passive DNS')
parser.add_argument('-i', "--ifcspec", help="select TRAP IFC specifier")
parser.add_argument('-t', "--threshold", default=5000, type=int, help="set number of JSON records per file")
args = parser.parse_args()

context = pytrap.TrapCtx()
context.init(['-i', args.ifcspec])

context.setRequiredFmt(0, pytrap.FMT_UNIREC, "")
unirec = pytrap.UnirecTemplate("ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST, "\
                               "time TIME_LAST,uint32 DNS_RR_TTL,uint32 PACKETS,uint16 DNS_ANSWERS,uint16 DNS_CLASS,"\
                               "uint16 DNS_ID,uint16 DNS_PSIZE,uint16 DNS_QTYPE,uint16 DNS_RLENGTH,uint16 DST_PORT,"\
                               "uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 DNS_DO,uint8 DNS_RCODE,"\
                               "uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL,string DNS_NAME,bytes DNS_RDATA")

records = list()
try:
    CONTENT_THRESHOLD = int(args.threshold)
except ValueError:
    sys.stderr.write("Argument to --threshold must be positive integer\n")
    exit(1)

# ===== main lopp =====
while True:
    try:
        data = context.recv()
    except pytrap.FormatMismatch:
        sys.stderr.write("Error: input data format mismatch.\n")
        break
    except pytrap.FormatChanged as e:
        fmttype, fmtspec = context.getDataFmt(0)
        unirec = pytrap.UnirecTemplate(fmtspec)
        data = e.data
        del(e)
        pass
    except pytrap.Terminated:
        break

    if len(data) <= 1:
        # flush to file remaining records
        if len(records) > 0:
            store_json(records)
        break

    packets_n = unirec.get(data, "PACKETS")
    # dns flow usually contains one packet
    if packets_n == 1:
        answers_n = unirec.get(data, "DNS_ANSWERS")
        src_port = unirec.get(data, "SRC_PORT")
        rcode = unirec.get(data, "DNS_RCODE")
        # reponse message should have at least one answer and have 53 as source port
        # and rcode with value 0 means no error happend
        if answers_n >= 1 and src_port == 53 and rcode == 0:
            # right now pdns support storage of A, AAAA and CNAME resource record types
            rr_type = unirec.get(data, "DNS_QTYPE")
            if rr_type not in (1, 5, 28):
                continue

            # For some flow the rcode contains value 1 but the response is type of CNAME
            if rr_type == 1:
                try:
                    socket.inet_aton(unirec.get(data, "DNS_RDATA").decode('utf-8'))
                except socket.error as e:
                    continue

            pdns_record = {
                "response": unirec.get(data, "DNS_RDATA").decode('utf-8'),
                "query": unirec.get(data, "DNS_NAME"),
                "ttl": unirec.get(data, "DNS_RR_TTL"),
                "type": unirec.get(data, "DNS_QTYPE"),
                "time_first": unirec.get(data, "TIME_FIRST").toDatetime().isoformat(),
                "time_last": unirec.get(data, "TIME_LAST").toDatetime().isoformat()
            }

            records.append(pdns_record)
            if len(records) >= CONTENT_THRESHOLD:
                store_json(records)
                records.clear()