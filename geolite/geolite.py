#!/usr/bin/python3
#
# Copyright (C) 2025 CESNET
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


import argparse
import pytrap
import geoip2.database


CITY_OUTPUTSPEC = "ipaddr ip, string country_name, string country_iso_code, uint32 country_geoname_id, uint32 is_in_european_union, string city_name, float latitude, float longitude, uint32 accuracy_radius"
COUNTRY_OUTPUTSPEC = "ipaddr ip, string name, string iso_code, uint32 geoname_id, uint32 is_in_european_union"
ASN_OUTPUTSPEC = "ipaddr ip, uint32 asn, string autonomous_system_organization"


parser = argparse.ArgumentParser(description='Module for geolocation using GeoLite2 database')
parser.add_argument('-i', "--ifcspec",
                    help="select TRAP IFC specifier")
parser.add_argument('-d', "--db",
                    help="path to the GeoLite2 database file",
                    required=True)
parser.add_argument('-f', "--fields",
                    help="input fields to use for geolocation seperated by comma",
                    default="SRC_IP")
parser.add_argument('-t', "--type",
                    help="type of GeoLite database",
                    choices=['country', 'city', 'asn'],
                    default="country")

# parse command line arguments
args = parser.parse_args()
fields = args.fields.split(',')


# initialize TRAP context
trap = pytrap.TrapCtx()
trap.init(['-i', args.ifcspec], 1, 1)

# output interface
fmttype = pytrap.FMT_UNIREC

# set the correct output specification based on the type of GeoLite database
if args.type == 'asn':
    outputspec = ASN_OUTPUTSPEC
elif args.type == 'city':
    outputspec = CITY_OUTPUTSPEC
else:
    outputspec = COUNTRY_OUTPUTSPEC
    
trap.setDataFmt(0, fmttype, outputspec)
output = pytrap.UnirecTemplate(outputspec)
output.createMessage()

# input interface
fmtspec = ""
trap.setRequiredFmt(0, fmttype, fmtspec)
rec = pytrap.UnirecTemplate(fmtspec)


# open GeoLite2 database reader
with geoip2.database.Reader(args.db) as reader:
    # main loop
    while True:
        try:
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmttype, fmtspec = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(fmtspec)
            data = e.data
        except pytrap.Terminated:
            print("Terminated trap.")
            break
        except pytrap.TrapError:
            print("Trap error, exiting.")
            break
        if len(data) <= 1:
            break

        else:
            rec.setData(data)
            for field in fields:
                ip = rec.get(data, field)
                output.ip = ip
                try:
                    if args.type == 'city':
                        geolocation = reader.city(str(ip))
                    elif args.type == 'country':
                        geolocation = reader.country(str(ip))
                    elif args.type == 'asn':
                        geolocation = reader.asn(str(ip))
                except:
                    continue
                if geolocation is None:
                    continue

                # fill output fields based on geolocation type
                if args.type == 'country':
                    output.name = geolocation.country.name or "unkown"
                    output.iso_code = geolocation.country.iso_code or "unkown"
                    output.geoname_id = geolocation.country.geoname_id or 0
                    output.is_in_european_union = geolocation.country.is_in_european_union or False
                elif args.type == 'city':
                    output.country_name = geolocation.country.name or "unkown"
                    output.country_iso_code = geolocation.country.iso_code or "unkown"
                    output.country_geoname_id = geolocation.country.geoname_id or 0
                    output.is_in_european_union = geolocation.country.is_in_european_union or False
                    output.city_name = geolocation.city.name or "unknown"
                    output.latitude = geolocation.location.latitude or 0.0
                    output.longitude = geolocation.location.longitude or 0.0
                    output.accuracy_radius = geolocation.location.accuracy_radius or 0
                elif args.type == 'asn':
                    output.asn = geolocation.autonomous_system_number or 0
                    output.autonomous_system_organization = geolocation.autonomous_system_organization or "unknown"

                # send output data
                trap.send(output.getData(), 0)

# send end-of-stream message and exit
trap.sendFlush(0)
trap.finalize()
