#################################################
# \file DSTCombinator.py                        #
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


from src.pyds.pyds2 import MassFunction


class DSTCombinator:
    """
    Wrapper class for the DST.
    """

    @staticmethod
    def combine(mlProba, tlsSniScore):
        """
        Method for combination the ML proba and the TLS SNI score by the DST.
        Parameters:
            mlProba: ML probability [0..1] of flow being a miner
            tlsSniScore: TLS SNI score from the TLS SNI Crypto Detector
        Returns: probability of flow being a miner, based on the pignistic function
        """

        mlBpa = MassFunction({
            'M': mlProba,
            'O': 1 - mlProba
        })

        tlsSniBpa = MassFunction({
            'M': tlsSniScore,
            'O': 1 - tlsSniScore
        })

        combinedBpa = mlBpa.combine_conjunctive(tlsSniBpa)
        combinedPignistic = combinedBpa.pignistic()

        return combinedPignistic['M']