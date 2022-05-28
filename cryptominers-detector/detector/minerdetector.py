#!/usr/bin/env python3


#################################################
# \file minerdetector.py                        #
# \author Richard Plny <plnyrich@fit.cvut.cz>   #
# \date 2022                                    #
#################################################


# BSD 3-Clause License
# 
# Copyright (c) 2022, CESNET
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


from src.MetaClassifier import MetaClassifier
import pytrap
import sys, argparse


### CONFIG ###
BUFFER_SIZE = 100000
ML_MODEL_PATH = './latest.pickle'
DST_THRESHOLD = 0.44
ML_THRESHOLD = 0.997
### CONFIG ###

### PYTRAP FORMATS DEFINITIONS ###
FMT_IN_SPECS = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint64 BYTES,uint64 BYTES_REV,uint32 PACKETS,uint32 PACKETS_REV,int8* PPI_PKT_DIRECTIONS,time* PPI_PKT_TIMES,uint16* PPI_PKT_LENGTHS,uint8* PPI_PKT_FLAGS,time TIME_FIRST,time TIME_LAST,string TLS_SNI,bytes IDP_CONTENT,bytes IDP_CONTENT_REV,uint8 PROTOCOL"
FMT_IN_SPECS_DEBUG = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint64 BYTES,uint64 BYTES_REV,uint32 PACKETS,uint32 PACKETS_REV,int8* PPI_PKT_DIRECTIONS,time* PPI_PKT_TIMES,uint16* PPI_PKT_LENGTHS,uint8* PPI_PKT_FLAGS,time TIME_FIRST,time TIME_LAST,string TLS_SNI,bytes IDP_CONTENT,bytes IDP_CONTENT_REV,uint8 PROTOCOL,string LABEL"
FMT_OUT_SPECS = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint64 BYTES,uint64 BYTES_REV,uint32 PACKETS,uint32 PACKETS_REV,int8* PPI_PKT_DIRECTIONS,time* PPI_PKT_TIMES,uint16* PPI_PKT_LENGTHS,uint8* PPI_PKT_FLAGS,time TIME_FIRST,time TIME_LAST,string TLS_SNI,bytes IDP_CONTENT,bytes IDP_CONTENT_REV,uint8 IS_MINER,uint8 REASON,uint8 PROTOCOL"
### PYTRAP FORMATS DEFINITIONS ###


def reasonToUint8(reason):
    """
    Function for the encoding the reason into uint8_t.
    Parameters:
        reason: 'S', 'D' or 'M'
    Returns: int (uint8_t)
    """
    if reason == 'S':
        return 1
    elif reason == 'D':
        return 2
    else:
        return 3


def processMinerFlows(pyCtx, flows, urOut):
    """
    Function for sending detected miner flows to the output interface.
    Parameters:
        pyCtx: pytrap context
        flows: list of miner flows
        out: UniRec format message
    """
    for flow, reason in flows:
        urOut.DST_IP = flow.DST_IP
        urOut.SRC_IP = flow.SRC_IP
        urOut.DST_PORT = flow.DST_PORT
        urOut.SRC_PORT = flow.SRC_PORT
        urOut.BYTES = flow.BYTES
        urOut.BYTES_REV = flow.BYTES_REV
        urOut.PACKETS = flow.PACKETS
        urOut.PACKETS_REV = flow.PACKETS_REV
        urOut.PPI_PKT_DIRECTIONS = flow.PPI_PKT_DIRECTIONS
        urOut.PPI_PKT_TIMES = flow.PPI_PKT_TIMES
        urOut.PPI_PKT_LENGTHS = flow.PPI_PKT_LENGTHS
        urOut.PPI_PKT_FLAGS = flow.PPI_PKT_FLAGS
        urOut.TIME_FIRST = flow.TIME_FIRST
        urOut.TIME_LAST = flow.TIME_LAST
        urOut.TLS_SNI = flow.TLS_SNI
        urOut.IDP_CONTENT = flow.IDP_CONTENT
        urOut.IDP_CONTENT_REV = flow.IDP_CONTENT_REV
        urOut.IS_MINER = 1
        urOut.REASON = reasonToUint8(reason)
        urOut.PROTOCOL = flow.PROTOCOL

        pyCtx.send(urOut.getData(), 0)


# Main
if __name__ == "__main__":
    # Arguments definition
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--model", help=f"Pickle file with ML model, default is {ML_MODEL_PATH}", type=str, default=ML_MODEL_PATH)
    parser.add_argument("-b", "--buffer", help=f"Flow buffer size, default is {BUFFER_SIZE}", type=int, default=BUFFER_SIZE)
    parser.add_argument("-i", help="IFC interfaces for pytrap", type=str)
    parser.add_argument("-d", "--dst-threshold", help=f"Threshold for miners' DST pignistic function [0..1], default is {DST_THRESHOLD}", type=float, default=DST_THRESHOLD)
    parser.add_argument("-t", "--ml-threshold", help=f"Threshold for ML proba [0..1], default is {ML_THRESHOLD}", type=float, default=ML_THRESHOLD)
    parser.add_argument("-v", "--verify-mode", help="Run detector in verification mode, flow labels are required", action='store_const', const=True)

    # Arguments parsing
    args = parser.parse_args()
    BUFFER_SIZE = args.buffer
    ML_MODEL_PATH = args.model
    DST_THRESHOLD = args.dst_threshold
    ML_THRESHOLD = args.ml_threshold
    DEBUG = args.verify_mode is not None

    # Arguments checks
    if BUFFER_SIZE <= 0:
        print('Bad value for buffer size!')
        exit(1)
    if DST_THRESHOLD < 0 or DST_THRESHOLD > 1:
        print('Bad value for DST threshold!')
        exit(1)
    if ML_THRESHOLD < 0 or ML_THRESHOLD > 1:
        print('Bad value for ML threshold!')
        exit(1)

    # Pytrap init
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 1, 1)

    fmtTypeIn = pytrap.FMT_UNIREC
    if DEBUG:
        fmtSpecIn = FMT_IN_SPECS_DEBUG
    else:
        fmtSpecIn = FMT_IN_SPECS

    trap.setRequiredFmt(0, fmtTypeIn, fmtSpecIn)
    rec = pytrap.UnirecTemplate(fmtSpecIn)

    out = pytrap.UnirecTemplate(FMT_OUT_SPECS)
    out.createMessage(8192)
    trap.setDataFmt(0, pytrap.FMT_UNIREC, FMT_OUT_SPECS)

    # Detector init
    detector = MetaClassifier(ML_MODEL_PATH, DST_THRESHOLD, ML_THRESHOLD, DEBUG)
    buffer = []

    # Main program loop
    loop = True
    while loop:
        try:
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmtTypeIn, fmtSpecIn = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(fmtSpecIn)
            data = e.data

        if len(data) <= 1:
            loop = False
        else:
            receivedFlow = rec.copy()
            receivedFlow.setData(data)

            # Drop flows with packets < 8 in at least one direction
            # and drop packets with PPI_PKT_FLAGS < 2 (for feature calculation)
            if receivedFlow.PACKETS < 8 or receivedFlow.PACKETS_REV < 8 or len(receivedFlow.PPI_PKT_FLAGS) < 2:
                continue

            buffer.append(receivedFlow)

            # If we filled buffer, process flows in bulk, send them to output IFC and clear the buffer
            if len(buffer) >= BUFFER_SIZE:
                minerFlows = detector.detectMiners(buffer)
                buffer = []
                processMinerFlows(trap, minerFlows, out)

    # If detector was stopped, send remaining flows from buffer to output IFC even if buffer was not filled
    if len(buffer) > 0:
        predicted = detector.detectMiners(buffer)
        processMinerFlows(trap, predicted, out)

    # Cleanup
    trap.finalize()

    # If detector ran in verification and evaluation mode, print statistics
    if DEBUG:
        detector.getMetrics().printMetrics()
