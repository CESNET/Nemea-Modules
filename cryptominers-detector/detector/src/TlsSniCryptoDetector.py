#################################################
# \file TlsSniCryptoDetector.py                 #
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


import pandas as pd
from src.TlsSniKeywordsMatcher import TlsSniKeywordsMatcher


class TlsSniCryptoDetector:
    """
       TlsSniCryptoDetector class.
       Implementation of the TLS SNI classifier.
    """

    def __init__(self, cryptoNames: list, cryptoKeywords: list):
        """
        Init.
        Parameters:
            cryptoNames: list of short cryptocurrency names
            cryptoKeywords: list of keywords signalizing mining process
        """
        self.cryptoNamesMatcher = TlsSniKeywordsMatcher(self.enhanceCryptoNames(cryptoNames))
        self.cryptoKeywordsMatcher = TlsSniKeywordsMatcher(cryptoKeywords)

    def doFlowSniDetection(self, tlsSni):
        """
        Method to calculate TLS SNI score.
        Parameters:
            tlsSni: string with the TLS SNI value
        Returns: TLS SNI score
        """
        tlsSniScore = 0
        if not pd.isnull(tlsSni) and len(tlsSni) > 0:
            tlsSniScore += self.cryptoNamesMatcher.find(tlsSni)
            tlsSniScore += self.cryptoKeywordsMatcher.find(tlsSni)
        return tlsSniScore / 2

    @staticmethod
    def enhanceCryptoNames(cryptoNames):
        """
        Static method to create enhanced rules from the crypto names list.
        Parameters:
            cryptoNames: list of short crypto names
        Returns: list of rules
        """
        enhanced = []
        for cryptoName in cryptoNames:
            enhanced.append(f'-{cryptoName}')
            enhanced.append(f'{cryptoName}-')
            enhanced.append(f'.{cryptoName}')
            enhanced.append(f'{cryptoName}.')
        return enhanced

    @staticmethod
    def getCryptoNames():
        """
        Static method - getter for short crypto names list.
        Returns: list of short crypto names
        """
        return [
            'BTC',
            'ETC',
            'XMR',
            'RVN',
        ]

    @staticmethod
    def getCryptoKeywords():
        """
        Static method - getter for keywords which signalize mining process.
        Returns: list of mining keywords
        """
        return [
            'POOL',
            'MINE',
            'MINING',
        ]
