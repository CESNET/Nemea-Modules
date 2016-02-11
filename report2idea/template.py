#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/ and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "something2idea"
MODULE_DESC = "Converts output of SOME_MODULE module to IDEA."
REQ_TYPE = trap.TRAP_FMT_UNIREC
REQ_FORMAT = "uint8 EVENT_TYPE,time TIME_FIRST,time TIME_LAST,ipaddr SRC_IP,ipaddr DST_IP,uint16 SRC_PORT,uint16 DST_PORT,uint8 PROTOCOL,uint32 EVENT_SCALE,string NOTE"

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)
    
    Return report in IDEA format (as Python dict)
    """
    idea={
            "Format": "IDEA0",
            "CreateTime": getIDEAtime(), # Set current time
            "DetectTime": getIDEAtime(
                # TODO Put here the right UniRec field or use without argument
            ),
            "Category": [
                # TODO Choose category from https://idea.cesnet.cz/en/classifications#eventtagsecurity_event_types_classification
            ],
            #"Source": [{
            #      "Proto": ["tcp"]
            # }],
            #"Target": [{
            #      "Proto": ["tcp"],
            #}],
            'Node': [{
                'Name': 'undefined',
                'SW': ['Nemea',
                    # TODO Put the name (string) of detector here.
                ],
            }],
            # TODO feel free to fill in any other fields from https://idea.cesnet.cz/en/definition
        }
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

