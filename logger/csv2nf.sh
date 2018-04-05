#!/bin/bash
#
#  \file csv2nf.sh
#  \brief Convert CSV file(s) from NEMEA logger into more readable format (nfdump-like)
#  \author Tomas Cejka <cejkat@cesnet.cz>
#  \date 2018
#
#  Copyright (C) 2018 CESNET
#
#  LICENSE TERMS
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#  3. Neither the name of the Company nor the names of its contributors
#     may be used to endorse or promote products derived from this
#     software without specific prior written permission.
#
#  ALTERNATIVELY, provided that this notice is retained in full, this
#  product may be distributed under the terms of the GNU General Public
#  License (GPL) version 2 or later, in which case the provisions
#  of the GPL apply INSTEAD OF those given above.
#
#  This software is provided ``as is'', and any express or implied
#  warranties, including, but not limited to, the implied warranties of
#  merchantability and fitness for a particular purpose are disclaimed.
#  In no event shall the company or contributors be liable for any
#  direct, indirect, incidental, special, exemplary, or consequential
#  damages (including, but not limited to, procurement of substitute
#  goods or services; loss of use, data, or profits; or business
#  interruption) however caused and on any theory of liability, whether
#  in contract, strict liability, or tort (including negligence or
#  otherwise) arising in any way out of the use of this software, even
#  if advised of the possibility of such damage.
#


if [ $# -lt 1 -o "$1" = "-h" ]; then
   echo $0 file.csv ...
   echo
   echo "Convert data from CSV file (stored by NEMEA logger) with header into
nfdump-like human readable format.  The script can process multiple CSV files,
however, they must have the equal templates (header - 1st line of each file).
Note1: Files are simply concatenated, there is no ordering.

If environmental variable SHORT_IP_ONLY is set to yes, flows with longer IP
are skipped (usually IPv6) - useful for readable traffic samples.

Examples:
   $0 file.csv
   $0 file1.csv file2.csv file3.csv
   SHORT_IP_ONLY=yes $0 file1.csv file2.csv
"
   exit 1
fi


awk -F, '
NR==1 {
   if (FNR==1) {
      head_backup=$0
   }
   for (i=1; i<=NF; i++) {
      sub("^[^ ]* ", "", $i); sub("PROTOCOL", "PROTO", $i)
   }
}

FNR==1 && NR!=1 {
   if (head_backup != $0) {
      print "Error: mismatching header in "FILENAME":"
      print "Original header: "head_backup
      print "Current header: "$0
      exit 1
   }
   next
}

{
   if (ENVIRON["SHORT_IP_ONLY"] == "yes" && length($2) >= 15) {
      # skip long IP addresses (IPv6)
      next
   }
   if (NR >=2) {
      sub(".[^.]*$", "", $5)
      sub(".[^.]*$", "", $6)
   }

   proto=($11 == 6?"TCP":($11 == 17?"UDP":($11 == 1?"ICMP":$11)))
   tcpflags=($12 == "TCP_FLAGS")?"TCPFLG":(and($12, 32)?"U":".")(and($12, 16)?"A":".")(and($12, 8)?"P":".")(and($12, 4)?"R":".")(and($12, 2)?"S":".")(and($12, 1)?"F":".")

   printf("%19s\t%19s\t%24s  ->  %24s\t%s\t%s\t%3s\t%5s\n",
         $5, $6, $2" : "$9, $1" : "$8, proto, tcpflags, $7, $3)
}' "$@"

