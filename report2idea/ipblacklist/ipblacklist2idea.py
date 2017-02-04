#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/ipblacklist and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "ipblacklist2idea"
MODULE_DESC = "Converts output of ipblacklistfilter module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,uint8 PROTOCOL,uint16 SRC_PORT,uint16 DST_PORT,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST,time TIME_FIRST,time TIME_LAST,uint32 EVENT_SCALE,uint32 PACKETS"



# Blacklist ID to name lookup table

bl_conv = {
   1 : 'Malware domains',
   2 : 'Zeus',
   4 : 'Spyeye',
   8 : 'Palevo',
   16 : 'Feodo',
   32 : 'Spamhaus',
   64 : 'Phishtank',
   128 : 'Tor'
}

proto_conv = {
    1 : 'icmp',
    6 : 'tcp',
    17 : 'udp',
}



# Blacklist ID to threshold lookup table
bl_scale_tholds = {
   1 : '1',
   2 : '1',
   4 : '1',
   8 : '1',
   16 : '1',
   32 : '40',
   64 : '1',
   128 : '150'
}


# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """
    global bl_conv, bl_scale_tholds

    blacklist = rec.SRC_BLACKLIST | rec.DST_BLACKLIST

    # report only: 'Malware domains', 'Zeus', 'Feodo', 'TOR'
    if blacklist not in [1, 2, 16, 128]:
        return None

    # report TOR only if '--enable-tor' option was passed
    if blacklist == 128 and not opts.enable_tor:
        return None

    export = False
    for i in range(0,8):
        if ((1<<i) & blacklist):
            if (rec.EVENT_SCALE >= int(bl_scale_tholds[1<<i])):
                export = True
                break
    if not export:
        return None

    tor = (blacklist == 128) # TOR is treated specially

    endTime = getIDEAtime(rec.TIME_LAST)
    protocol = ""
    if rec.PROTOCOL in proto_conv:
        protocol = proto_conv[rec.PROTOCOL]
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "DetectTime": endTime,
        'CeaseTime': endTime,
        "Category": [ "Intrusion.Botnet" ] if not tor else [ "Suspicious.TOR" ],
        "PacketCount": rec.PACKETS,
        "ByteCount": rec.BYTES,

        "Source": [],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'ipblacklistfilter' ],
            'Type': [ 'Flow', 'Blacklist' ]
        }],
    }

    if rec.DST_IP:
        addr = {
            "Proto": [ protocol ]
        }
        if rec.PROTOCOL != 1:
            addr["Port"] = [ rec.DST_PORT ]
        setAddr(addr, rec.DST_IP)

        if tor:
            if rec.DST_BLACKLIST:
                addr["Type"] = [ "TOR" ]
            else:
                pass # don't set Type for address contacted by TOR exit node
        else:
            if rec.DST_BLACKLIST:
                addr["Type"] = [ "Botnet", "CC" ]
                idea['Note'] = 'Destination IP {0} was found on blacklist.'.format(rec.DST_IP)
            else:
                addr["Type"] = [ "Botnet" ]
        idea['Source'].append(addr)

    if rec.SRC_IP:
        addr = {
            "Proto": [ protocol ]
        }
        if rec.PROTOCOL != 1:
            addr["Port"] = [ rec.SRC_PORT ]
        setAddr(addr, rec.SRC_IP)

        if tor:
            if rec.SRC_BLACKLIST:
                addr["Type"] = [ "TOR" ]
            else:
                pass # don't set Type for address contacting TOR exit node
        else:
            if rec.SRC_BLACKLIST:
                addr["Type"] = [ "Botnet", "CC" ]
                idea['Note'] = 'Source IP {0} was found on blacklist.'.format(rec.SRC_IP)
            else:
                addr["Type"] = [ "Botnet" ]
        idea['Source'].append(addr)

    if rec.SRC_BLACKLIST:
        if tor:
            descSRC = "{0} which is TOR exit node".format(rec.SRC_IP)
        else:
            descSRC = "{0} which is on {1} blacklist".format(rec.SRC_IP, bl_conv[rec.SRC_BLACKLIST])
        descDST = "{0}".format(rec.DST_IP)
    else:
        if tor:
            descDST = "{0} which is TOR exit node".format(rec.DST_IP)
        else:
            descDST = "{0} which is on {1} blacklist".format(rec.DST_IP, bl_conv[rec.DST_BLACKLIST])
        descSRC = "{0}".format(rec.SRC_IP)
    idea['Description'] = "{0} connected to {1}.".format(descSRC, descDST)
    return idea


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
parser = argparse.ArgumentParser()
parser.add_argument('--enable-tor', action='store_true',
                    help="Don't skip alerts about communication with TOR exit nodes (they are ignored by default)")

# Run the module
if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = parser
    )

