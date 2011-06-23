#!/bin/bash

# Script for generation "oui.h" file (netdiscover program at
#   http://nixgeneration.com/~jaime/netdiscover/
#
# Obtain data from internet source at:
# lynx -source  http://standards.ieee.org/regauth/oui/oui.txt >oui.txt
#
# Syntax: oui.txt2oui.h_netdiscover
#
# Script generate src/oui.h file.
#
# 16-May-2009 Frantisek Hanzlik <franta@hanzlici.cz>
#**********************************************************************
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#

JA=${0##*/}
DATE=$(date +'%Y%m%d')
ORIGF=oui.txt
DSTD=src
DSTF=oui.h
URL="http://standards.ieee.org/regauth/oui/oui.txt"
TMPF=$ORIGF-$DATE
AWK="gawk"
#AWK="mawk"
#AWK="awk"

[ -d "$DSTD" ] || { echo "$JA: Destdir \"$DSTD\" not exist!"; exit 1; }
#if ! [ -f "$TMPF" -a -s "$TMPF" ]; then
#   echo "Trying download \"$ORIGF\" with lynx..."
#   if ! lynx -source $URL >"$TMPF"; then
#      echo "Trying download \"$ORIGF\" with elinks..."
#      if ! elinks -source $URL >"$TMPF"; then
#         echo "Trying download \"$ORIGF\" with wget..."
#         if ! wget --quiet --output-document="$TMPF" $URL; then
#            echo "$JA: Cann't obtain \"$URL\"!"
#            exit 1
#         fi
#      fi
#   fi
#else
#   echo "\"$TMPF\" already exist, skipping download..."
#fi
if ! [ -f "$TMPF" -a -s "$TMPF" ]; then
  echo -n "Trying download \"$ORIGF\" with lynx..."
  if [[ -x /usr/bin/lynx ]]; then
    lynx -source $URL >"$TMPF"
  else
     echo -n " with elinks..."
     if [[ -x /usr/bin/elinks ]]; then
       elinks -source $URL >"$TMPF"
     else
        echo " with wget..."
        if [[ -x /usr/bin/wget ]]; then
          wget --quiet --output-document="$TMPF" $URL
        else
           echo "$JA: Can't obtain \"$URL\"!"
           exit 1
        fi
     fi
  fi
else
   echo -n "\"$TMPF\" already exist, skipping download..."
fi
echo ""

echo "Process oui.txt (\"$TMPF\")..."

# if RS is null string, then records are separated by blank lines...
# but this isn't true in oui.txt

LANG=C $AWK --re-interval --assign URL="$URL" '
BEGIN {
	RS = "\n([[:blank:]]*\n)+";
	FS = "\n";
	MI = "";
	NN = 0;
	printf( \
	  "/*\n" \
	  " * Organizationally Unique Identifier list at date %s\n" \
	  " * Automatically generated from %s\n" \
	  " * For Netdiscover by Jaime Penalba\n" \
	  " *\n" \
	  " */\n" \
	  "\n" \
	  "struct oui {\n" \
	  "   char *prefix;   /* 24 bit global prefix */\n" \
	  "   char *vendor;   /* Vendor id string     */\n" \
	  "};\n" \
	  "\n" \
	  "struct oui oui_table[] = {\n", strftime("%d-%b-%Y"), URL);
}

(/[[:xdigit:]]{6}/) {
	N1 = split($1,A1,/\t+/);
	N2 = split($2,A2,/\t+/);
	N3 = split(A2[1],PN,/ +/);
#	printf("%i,%i,%i>%s<>%s<>%s< $1=%s<, $2=%s<, $3=%s<.\n",N1,N2,N3,PN[1],A1[2],A2[2],$1,$2,$3);
#	V1 = gensub(/^[[:punct:]]+/,"",1,A1[2]);
#	V2 = gensub(/^[[:punct:]]+/,"",1,A2[2]);
	V1 = gensub(/^[[:blank:]]+/,"",1,A1[2]);
	V2 = gensub(/^[[:blank:]]+/,"",1,A2[2]);
	V0 = V2;
	if (V0 ~ /^[[:blank:]]*$/) {
		V0 = V1;
	}
	V = gensub(/\"/,"\\\\\"","g",V0);
	if (MI != "")
		printf("   { \"%s\", \"%s\" },\n", MI, MV);
	MI = PN[1];
	MV = V;
	NN++;
}

END {
	printf( \
	  "   { \"%s\", \"%s\" },\n" \
	  "   { NULL, NULL }\n" \
	  "};\n" \
	  "\n" \
	  "// Total %i items.\n", MI, MV, NN);
}' <"$TMPF" >"$DSTD/$DSTF"

if [ $? -ne 0 ]; then
  echo "$JA: $TMPF parsing error !"
  exit 1
else
  echo "All OK"
  ls -oh oui.txt-* src/oui.h
fi
