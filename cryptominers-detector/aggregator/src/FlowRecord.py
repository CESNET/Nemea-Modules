#################################################
# \file FlowRecord.py                           #
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


from time import time
import pytrap


class FlowRecord:
    """
    FlowRecord class.
    Represents one record in the flow cache.
    """
    def __init__(self, firstFlow):
        """
        Init.
        Parameters:
            firstFlow: first flow of the record
        """
        self.srcIp = firstFlow.SRC_IP
        self.dstIp = firstFlow.DST_IP
        self.srcPort = firstFlow.SRC_PORT
        self.dstPort = firstFlow.DST_PORT
        self.eventTime = firstFlow.TIME_FIRST
        self.detectTime = firstFlow.TIME_LAST
        self.reasons = {
            '1': 0,
            '2': 0,
            '3': 0
        }
        self.flows = 0
        self.packets = 0
        self.bytes = 0
        self.lastUpdate = 0
        self.winStartTime = pytrap.UnirecTime.now()
        self.update(firstFlow)

    def update(self, flow):
        """
        Method to update statistics based on the newly received flow.
        Parameters:
            flow: newly received flow
        """
        self.flows += 1
        self.reasons[str(flow.REASON)] += 1
        self.packets += flow.PACKETS + flow.PACKETS_REV
        self.bytes += flow.BYTES + flow.BYTES_REV
        # Update last activity timestamp
        self.lastUpdate = time()

    def ready(self, activeTimeout, passiveTimeout):
        """
        Method to check if record is ready to be exported.
        Parameters:
            activeTimeout: active timeout
            passiveTimeout: passive timeout
        Returns: True if flow should be exported, otherwise False
        """
        return time() - self.lastUpdate >= passiveTimeout or self.flows >= activeTimeout

    def reasonToStr(self):
        """
        Method for getting the most dominant detection method.
        Returns: 'STRATUM', 'DST' or 'ML'
        """
        # dominant is STRATUM
        if self.reasons['1'] >= self.reasons['2'] and self.reasons['1'] >= self.reasons['3']:
            return 'STRATUM'
        # dominant is DST
        if self.reasons['2'] >= self.reasons['1'] and self.reasons['2'] >= self.reasons['3']:
            return 'DST'
        # dominant is ML
        return 'ML'
