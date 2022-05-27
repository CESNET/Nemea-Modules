#!/usr/bin/python3


#################################################
# \file mineraggregator2idea.py                 #
# \author Richard Plny <plnyrich@fit.cvut.cz>   #
# \date 2022                                    #
#################################################


# BSD 3-Clause License
# 
# Copyright (c) 2022, Richard Plny
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import argparse
from report2idea import *


# Module name, description and required input data format
MODULE_NAME = "miner_detector_ml"
MODULE_DESC = "Converts output of minerdetector and mineraggregator module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint64 FLOWS_TOTAL,uint64 BYTES_TOTAL,uint64 PACKETS_TOTAL,time EVENT_TIME,time DETECT_TIME,string DETECTION_SOURCE,time WIN_START_TIME,time WIN_END_TIME"


# Main conversion function
def convert_to_idea(rec, opts=None):
    endTime = getIDEAtime(rec.DETECT_TIME)
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.EVENT_TIME),
        "DetectTime": endTime,
        "CeaseTime": endTime,
        "Category": [ "Suspicious.Miner" ],
        "Source": [{
              "Proto": [ 'tcp' ]
         }],
        "Target": [{
              "Proto": [ 'tcp' ]
        }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'miner_detector_ml' ],
            'Type': [ 'Flow', 'Statistical', 'Signature' ]
        }],
    }

    idea['FlowCount'] = rec.FLOWS_TOTAL
    idea['PacketCount'] = rec.PACKETS_TOTAL
    idea['ByteCount'] = rec.BYTES_TOTAL
    idea['WinStartTime'] = getIDEAtime(rec.WIN_START_TIME)
    idea['WinEndTime'] = getIDEAtime(rec.WIN_END_TIME)

    """
    TODO:
        * Better Module Name.
        * Own Module Description.
        * Node, Note & Description - Own string texts.
    """

    setAddr(idea['Source'][0], rec.SRC_IP)
    setAddr(idea['Target'][0], rec.DST_IP)
    idea['Note'] = 'Source IP {0} might be a miner.'.format(rec.SRC_IP)
    idea['Description'] = "{0} might be a miner (connected to {1}:{2}). Based on `{3}`".format(rec.SRC_IP, rec.DST_IP, rec.DST_PORT, rec.DETECTION_SOURCE)
    return idea


if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = None
    )
