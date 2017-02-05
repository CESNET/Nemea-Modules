#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/dnstunnel and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "dnstunnel2idea"
MODULE_DESC = "Converts output of dnstunnel_detection module to IDEA."
REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr SRC_IP,time TIME_FIRST,time TIME_LAST,uint32 EVENT_ID,uint32 TUNNEL_CNT_PACKET,float TUNNEL_PER_NEW_DOMAIN,float TUNNEL_PER_SUBDOMAIN,uint8 TUNNEL_TYPE,string TUNNEL_DOMAIN"

dataLocation = {
    5: " in TXT field",
    6: " in CNAME field",
    7: " in MX field",
    8: " in NS field"
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
    endTime = getIDEAtime(rec.TIME_LAST)
    idea={
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        'CeaseTime': endTime,
        "DetectTime": endTime,
        "Category": [ 'Anomaly.Connection' ],
        "FlowCount": rec.TUNNEL_CNT_PACKET,
        "Source": [{
            "Proto": ["udp", "dns"]
        }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'dnstunnel_detection' ],
            'Type': [ 'Flow', 'Statistical', 'Content' ]
        }],
    }
    setAddr(idea['Source'][0], rec.SRC_IP)
    if rec.TUNNEL_TYPE in (1, 4, 5, 6, 7, 8):
        idea['Description'] = "Communication tunnel over DNS"
        if rec.TUNNEL_TYPE == 1:
            idea['Description'] = idea['Description'] + " observed in requests"
        else:
            idea['Description'] = idea['Description'] + " observed in responses"
            if rec.TUNNEL_TYPE in dataLocation:
                idea['Note'] = "Data in {0}".format(dataLocation[rec.TUNNEL_TYPE])
        idea["Note"] = "Example of used domain name: {0}".format(''.join([i if ord(i) < 128 else '?' for i in rec.TUNNEL_DOMAIN]))
    else:
        return None
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
        arg_parser = None # (optional) Instance of argparse.ArgumentParser with some arguments defined can be passed - these arguments are then parsed from command line and passed to the conv_func)
    )

