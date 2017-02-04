#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/minerdetector and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "minerdetector2idea"
MODULE_DESC = "Converts output of minerdetector module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,time TIME_FIRST,time TIME_LAST,uint32 EVENT_SCALE,uint16 DST_PORT"


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
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "DetectTime": endTime,
        'CeaseTime': endTime,
        "Category": [ "Suspicious.Miner" ],
        "Source": [{
              "Proto": [ 'tcp' ]
         }],
        "Target": [{
              "Proto": [ 'tcp' ]
        }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'minerdetector' ],
            'Type': [ 'Flow', 'Blacklist' ]
        }],
    }

 
    idea['FlowCount'] = rec.EVENT_SCALE
    idea['ConnCount'] = rec.EVENT_SCALE
    setAddr(idea['Source'][0], rec.SRC_IP)
    setAddr(idea['Target'][0], rec.DST_IP)
    idea['Note'] = 'Source IP {0} might be a miner.'.format(rec.SRC_IP)
    idea['Description'] = "{0} might be a miner, because it connected to {1}:{2} which is flagged as a mining pool server.".format(rec.SRC_IP, rec.DST_IP, rec.DST_PORT)
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

