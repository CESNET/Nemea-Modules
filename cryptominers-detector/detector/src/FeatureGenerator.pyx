#################################################
# \file FeatureGenerator.pyx                    #
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


import numpy as np
import cython


def getFeatures(PPI_PKT_DIRECTIONS, PPI_PKT_TIMES, PPI_PKT_LENGTHS, PPI_PKT_FLAGS):
    """
    Function used for calculation of features for the ML.
    Parameters:
        PPI_PKT_DIRECTIONS: list of 1s and -1s, representing packet directions
         PPI_PKT_TIMES: list with timestamps
         PPI_PKT_LENGTHS: list of packet lengths
         PPI_PKT_FLAGS: list of ints, representing TCP flags
    Returns: tuple of features in the following order:
             SENT_PERCENTAGE, RECV_PERCENTAGE, IS_REQUEST_RESPONSE, AVG_SECS_BETWEEN_PKTS, AVG_PKT_LEN, PSH_RATIO
    """

    # Calculate ratio of sent/received packets in the flow
    cnt: cython.int = len(PPI_PKT_DIRECTIONS)
    sent = PPI_PKT_DIRECTIONS.count(1) / cnt
    # Sent and received ratios are complementary, their is has to be one
    # Save time by simple arithmetics
    recv = 1 - sent
    reqres = sent == 0.5

    # Calculate array with number of seconds between each two packets
    # And then calculate the average idle time between two packets
    intervalCnt: cython.int = 0
    intervalSum: cython.int = 0
    i: cython.int = 0
    for i in range(1, len(PPI_PKT_TIMES)):
        intervalSum += PPI_PKT_TIMES[i].getSeconds() - PPI_PKT_TIMES[i - 1].getSeconds()
        intervalCnt += 1
    avgTimeBetween = intervalSum / intervalCnt

    # Average length (size) of a packet in flow
    avgPktLen = np.mean(PPI_PKT_LENGTHS)

    # Calculate ratio of packets in flow with TCP PUSH flag set
    pshCnt: cython.int = 0
    tcpFlags: cython.int
    for tcpFlags in PPI_PKT_FLAGS:
        tcpFlags = int(tcpFlags)
        pshCnt += tcpFlags & 8
    pshRatio =  (pshCnt // 8) / len(PPI_PKT_FLAGS)

    return sent, recv, reqres, avgTimeBetween, avgPktLen, pshRatio
