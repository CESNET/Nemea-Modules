#!/usr/bin/env python

from common import Run
import trap
import argparse


# Moudle name, description and required input data format
MODULE_NAME = "something2idea"
MODULE_DESC = "Converts output of SOME_MODULE module to IDEA."
REQ_TYPE = trap.TRAP_FMT_UNIREC
REQ_FORMAT = "uint8 EVENT_TYPE,time TIME_FIRST,time TIME_LAST,ipaddr SRC_IP,ipaddr DST_IP,uint16 SRC_PORT,uint16 DST_PORT,uint8 PROTOCOL,double EVENT_SCALE,string NOTE"

# Main conversion function
# rec - Record recevied on TRAP input interface (the report to convert). Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
# opts - options parsed from command line (as returned by argparse.ArgumentParser)
# Return report in IDEA format (as Python dict)
def convert_to_idea(rec, opts=None):
    return {'test': 1, 'test2': 'hello'}



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
