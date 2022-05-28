#################################################
# \file StratumDetector.py                      #
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


import re2


class StratumDetector:
    """
    Stratum Detector class.
    """
    def __init__(self):
        self.compiled = dict()
        self.compileRegex()

    def compileRegex(self):
        """
        Method which prepares compiled Regex patterns for later matching.
        """
        self.compiled["STRATUM"] = re2.compile(
            r'("(jsonrpc|method|worker)":\s?")|(params":|mining\.(set|not))'
        )
        self.compiled["STRATUM_RESPONSE"] = re2.compile(
            r'(("(?P<I>id)|(?P<R>result)|(?P<E>error)":\s?).*){3,}'
        )

    def containsStratum(self, rawContent):
        """
        Method for detection of Stratum mining protocol.
        Parameters:
            rawContent: hex string, flow's IDP_CONTENT or IDP_CONTENT_REV
        Returns: True if Stratum was matched, otherwise False
        """
        content = self.convertHexString(rawContent)
        if self.compiled["STRATUM"].search(content):
            return True
        r = self.compiled["STRATUM_RESPONSE"].search(content)
        return r is not None and r.group(3) is not None and r.group(4) is not None and r.group(5) is not None

    def doStratumDetection(self, idpContent, idpContentRev):
        return self.containsStratum(idpContent) or self.containsStratum(idpContentRev)

    @staticmethod
    def convertHexString(content):
        """
        Static method for decoding the IDP_CONTENT and IDP_CONTENT_REV fields of flow.
        Parameters:
            content: hex string
        Returns: decoded string
        """
        return content.decode('iso-8859-1')
