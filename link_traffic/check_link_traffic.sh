#!/bin/bash
#script checks whether all links are transferring data

# Path to socket of link_traffic module:
SOCKPATH=/var/run/libtrap/munin_link_traffic
OUTPUTPATH=/tmp/link_traffic_output
pf="/tmp/`basename $0`-prevval"

#getting current output of munin_link_traffic script
nc -U "$SOCKPATH" </dev/null 2>/dev/null >"$OUTPUTPATH"
headers="`cat "$OUTPUTPATH" | awk 'NR==1' | tr ',' ' '`"
curval="`cat "$OUTPUTPATH" | awk 'NR==2' | tr ',' ' '`"
curtime="`date +%s`"

if [ -z "$curval" ]; then
   echo "Cannot read from socket. Is the module running?"
   exit 2
fi

if [ `echo "$headers" | wc -w` -ne `echo "$curval" | wc -w` ]; then
   echo "Configuration has changed.\n"
   exit 1
fi

#checking if there is any previous value and creating one if there was not
if [ -e "$pf" ]; then
  prevval=`cat "$pf" | head -2`
else
  prevval=`echo -e "$curval\n$curtime"`
fi

prevtime="`echo "$prevval" | awk 'FNR==2'`"
prevval="`echo "$prevval" | awk 'FNR==1'`"
echo -e "$curval\n$curtime" > "$pf"
down_flag=0

#comparing values in curval and prev val
#if they are the same shell exits with critical 2 (one link is down)
if [ "$curtime" -ne "$prevtime" ]; then
   counter=0
   for i in `echo "$curval"`; do
      counter=$(($counter+1))
      previous=`echo "$prevval" | cut -d' ' -f"$counter"`
      if [ "$i" -eq "$previous" ]; then
         #appending the link that is currently down to list of downed links
         old_down="$new_down"
         new_down=`echo "$headers" | cut -d' ' -f"$counter" | cut -d'-' -f1`
         if [ "$new_down" != "$old_down" ]; then
            link_down=`echo "$link_down $new_down"`
         fi
         down_flag=1
      fi
   done
fi
#checking if there is link down
if [ "$down_flag" -eq 1 ]; then
   echo "Links$link_down are DOWN."
   exit 2
else
   echo "All links are UP."
   exit 0
fi
