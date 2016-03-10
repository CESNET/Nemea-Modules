#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/ and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "ipblacklist2idea"
MODULE_DESC = "Converts output of ipblacklistfilter module to IDEA."

REQ_TYPE = trap.TRAP_FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 LINK_BIT_FIELD,uint64 SRC_BLACKLIST,time TIME_FIRST,time TIME_LAST,uint32 EVENT_SCALE,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL"



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

    # report only: 'Malware domains', 'Zeus', 'Feodo'
    if blacklist not in [1, 2, 16]:
        return None

    export = False
    for i in range(0,8):
        if ((1<<i) & blacklist):
            if (rec.EVENT_SCALE >= int(bl_scale_tholds[1<<i])):
                export = True
                break
    if not export:
        return None

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
        "Category": [ "Intrusion.Botnet" ],
        "PacketCount": rec.PACKETS,
        "ByteCount": rec.BYTES,

        "Source": [{
              "Proto": [ protocol ]
         }],
        "Target": [{
              "Proto": [ protocol ]
        }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'ipblacklistfilter' ],
            'Type': [ 'Flow', 'Blacklist' ]
        }],
    }

    if rec.DST_IP != 0:
        if rec.DST_BLACKLIST:
            setAddr(idea['Source'][0], rec.DST_IP)
            idea['Note'] = 'Destination IP {} was found on blacklist.'.format(rec.DST_IP)
        else:
            setAddr(idea['Target'][0], rec.DST_IP)

    if rec.SRC_IP != 0:
        if rec.SRC_BLACKLIST:
            setAddr(idea['Source'][0], rec.SRC_IP)
            idea['Note'] = 'Source IP {} was found on blacklist.'.format(rec.SRC_IP)
        else:
            setAddr(idea['Target'][0], rec.SRC_IP)

    if rec.SRC_BLACKLIST:
        descSRC = "{} which is on {} blacklist".format(rec.SRC_IP, bl_conv[rec.SRC_BLACKLIST])
        descDST = "{}".format(rec.DST_IP)
    else:
        descDST = "{} which is on {} blacklist".format(rec.DST_IP, bl_conv[rec.DST_BLACKLIST])
        descSRC = "{}".format(rec.SRC_IP)
    idea['Description'] = ["{} connected to {}.".format(descSRC, descDST)]
    return idea


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
#parser = argparse.ArgumentParser()

# Run the module
if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = None
    )

