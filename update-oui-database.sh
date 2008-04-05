#!/bin/sh

##############################################################################
#            update-oui-database.sh
#
#  Thu Apr  3 21:18:44 CEST 2008
#  Copyright  2008  Jaime Penalba Estebanez
#  jpenalbae@gmail.com
##############################################################################

#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#


TOUTFILE=oui.h
DESTFILE=src/oui.h

# Check we are on base dir
if [ ! -f $DESTFILE ]
then
   echo "This script must be run at base dir. Exiting."
   exit 1
fi


# Download updated oui.txt file
if [ ! -f oui.txt ]
then
   wget "http://standards.ieee.org/regauth/oui/oui.txt"
fi

# Check if download is ok
if [ ! -f oui.txt ]
then
   echo "Download failed. Exiting."
   exit 1
else
   echo "Download OK. Generating oui.h, it may take some time."
fi


# Include header
printf "/*
 * Organizationally Unique Identifier list - `date`
 * Automatically generated from http://standards.ieee.org/regauth/oui/oui.txt
 * For Netdiscover by Jaime Penalba
 *
 */\n\n" > $TOUTFILE

# Include oui struct
printf "struct oui {
   char *prefix;   /* 24 bit global prefix */
   char *vendor;   /* Vendor id string     */
};\n\n" >> $TOUTFILE

# Main data structure
printf "struct oui oui_table[] = {\n" >> $TOUTFILE

# Add each vendor
cat oui.txt | grep "(base 16)" | while read LINE
do
   MAC=`echo $LINE | awk '{ print $1 }'`
   VENDOR=`echo $LINE | awk '{ print $4 " " $5 " " $6 " " $7 }' | sed 's/[ \t]*$//' | sed "s/\"/'/g"`

   if [ "X$VENDOR" == "X" ]
   then
      VENDOR="PRIVATE"
   fi

   printf "   { \"$MAC\", \"$VENDOR\" },\n" >> $TOUTFILE
done

# End of data structure
printf "   { NULL, NULL }\n};\n\n" >> $TOUTFILE


# Write new file
mv -f $DESTFILE ${DESTFILE}.old
mv $TOUTFILE $DESTFILE

echo "Generation complete. Please check $DESTFILE before compiling"
echo "Exiting."
exit 0
