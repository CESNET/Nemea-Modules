#!/usr/bin/env python3


#################################################
# \file mineraggregator.py                      #
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


from threading import Thread
import pytrap
import sys, time, argparse
from src.FlowCache import FlowCache


### CONFIG ###
ACTIVE_TIMEOUT = 5 # flows
PASSIVE_TIMEOUT = 30 # minutes
REPORT_INTERVAL = 5 # seconds
SHOULD_CONTINUE = True

### PYTRAP FORMATS DEFINITIONS ###
IN_SPECS = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint8 PROTOCOL,uint64 BYTES,uint64 BYTES_REV,uint32 PACKETS,uint32 PACKETS_REV,time TIME_FIRST,time TIME_LAST,uint8 REASON"
OUT_SPEC = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint64 FLOWS_TOTAL,uint64 BYTES_TOTAL,uint64 PACKETS_TOTAL,time EVENT_TIME,time DETECT_TIME,string DETECTION_SOURCE,time WIN_START_TIME,time WIN_END_TIME"
### PYTRAP FORMATS DEFINITIONS ###

# Pytrap `stop` definition
stop = False


def sendToOutput(trapCtx, outUr, data):
    """
    Function for sending alerts to output IFC.
    Parameters:
        trapCtx: pytrap context
        outUr: output UniRec message
        data: alerts to send
    """
    winEndTime = pytrap.UnirecTime.now()
    for flowRecord in data:
        outUr.SRC_IP = flowRecord.srcIp
        outUr.DST_IP = flowRecord.dstIp
        outUr.SRC_PORT = flowRecord.srcPort
        outUr.DST_PORT = flowRecord.dstPort
        outUr.EVENT_TIME = flowRecord.eventTime
        outUr.DETECT_TIME = flowRecord.detectTime
        outUr.FLOWS_TOTAL = flowRecord.flows
        outUr.PACKETS_TOTAL = flowRecord.packets
        outUr.BYTES_TOTAL = flowRecord.bytes
        outUr.DETECTION_SOURCE = flowRecord.reasonToStr()
        outUr.WIN_START_TIME = flowRecord.winStartTime
        outUr.WIN_END_TIME = winEndTime

        trapCtx.send(outUr.getData(), 0)


def flowExporter(trapCtx, outUr, cache, interval):
    """
    Function for periodical checks and exporting flows from flow cache and sending them to output IFC.
    Parameters:
        trapCtx: pytrap context
        outUr: output UniRec message
        cache: flow cache
        interval: how long should reporting thread sleep before the next check of flow cache
    """
    global SHOULD_CONTINUE
    while SHOULD_CONTINUE:
        dataToExport = cache.toExport()
        if dataToExport:
            sendToOutput(trapCtx, outUr, dataToExport)
        time.sleep(interval)
    dataToExport = cache.getAll()
    if dataToExport:
        sendToOutput(trapCtx, outUr, dataToExport)


# Main
if __name__ == "__main__":
    # Arguments definition
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--export-interval", help=f"Number of seconds the export thread periodically sleeps, default is {REPORT_INTERVAL} seconds", type=int, default=REPORT_INTERVAL)
    parser.add_argument("-a", "--active-timeout", help=f"Max number of flows, when this number is reached, data are sent to out IFC, default is {ACTIVE_TIMEOUT} flows", type=int, default=ACTIVE_TIMEOUT)
    parser.add_argument("-p", "--passive-timeout", help=f"Number of minutes, when this number of minutes passed from last activity, data are sent to out IFC, default is {PASSIVE_TIMEOUT} minutes", type=int, default=PASSIVE_TIMEOUT)
    parser.add_argument("-i", help="IFC interfaces for pytrap", type=str)

    # Arguments parsing
    args = parser.parse_args()
    REPORT_INTERVAL = args.export_interval
    ACTIVE_TIMEOUT = args.active_timeout
    PASSIVE_TIMEOUT = args.passive_timeout * 60 # to seconds

    # Flow cache init
    flowCache = FlowCache(ACTIVE_TIMEOUT, PASSIVE_TIMEOUT)

    # Pytrap init
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 1, 1)

    fmtTypeIn = pytrap.FMT_UNIREC
    fmtSpecIn = IN_SPECS

    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, IN_SPECS)
    rec = pytrap.UnirecTemplate(fmtSpecIn)

    out = pytrap.UnirecTemplate(OUT_SPEC)
    out.createMessage(8192)
    trap.setDataFmt(0, pytrap.FMT_UNIREC, OUT_SPEC)

    # Start the reporting and exporting thread
    reportThread = Thread(target = flowExporter, args = (trap, out, flowCache, REPORT_INTERVAL))
    reportThread.start()

    # Main program loop
    while not stop and SHOULD_CONTINUE:
        try:
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmtTypeIn, fmtSpecIn = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(fmtSpecIn)
            data = e.data
        except KeyboardInterrupt:
            SHOULD_CONTINUE = False
            break

        if len(data) <= 1:
            SHOULD_CONTINUE = False
        else:
            receivedFlow = rec.copy()
            receivedFlow.setData(data)

            flowCache.update(receivedFlow)

    # Cleanup
    reportThread.join()
    trap.finalize()
