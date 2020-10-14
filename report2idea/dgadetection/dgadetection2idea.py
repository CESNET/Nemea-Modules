#!/usr/bin/python3


# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "dgadetection"
MODULE_DESC = "Converts output of DGA_detector module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr SRC_IP,ipaddr DST_IP,time TIME_FIRST,time TIME_LAST,string DNS_Q_NAME"


# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    
    """
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "DetectTime": getIDEAtime(rec.TIME_LAST),
        "CreateTime": getIDEAtime(),
        "Category": [ "Intrusion.Botnet","Test" ],
        "Description": "Botnet trying to comunicate with control server using DGA",
        "Source": [{
            # Bot (address filled below)
            "Type": ["Botnet"]
        },
        {
            # CC server:
            "Type": ["Botnet", "CC"],
            "Hostname": [rec.DNS_Q_NAME]
        }],
        'Node': [{
            'SW': [ 'Nemea', 'DGA_detector' ]
        }],
    }
    setAddr(idea['Source'][0], rec.SRC_IP)
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

