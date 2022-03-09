#!/bin/bash

# Script for generation "oui.h" file netdiscover

# Syntax: oui.txt2oui.h_netdiscover
#
# Script generate src/oui.h file.
#**********************************************************************
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#

set -euo pipefail

DATE=$(date +'%Y%m%d')
ORIGF="oui.txt"
DSTD="src"
DSTF="oui.h"
URL="http://standards-oui.ieee.org/oui.txt"
TMPF="${ORIGF}-${DATE}"

if [ ! -d ${DSTD} ]; then
	echo "Directory ${DSTD} does not exist."
	exit 1
fi

if ! [ -f "$TMPF" -a -s "$TMPF" ]; then
	echo "Trying download \"$ORIGF\" with lynx..."
	if type "lynx" >/dev/null; then
		lynx -source $URL >"$TMPF"
	else
		echo " with elinks..."
		if type "elinks" >/dev/null; then
			elinks -source $URL >"$TMPF"
		else
			echo " with wget..."
			if type "wget" >/dev/null; then
				wget --quiet --output-document="$TMPF" $URL
			else
				echo " with curl..."
				if type "curl" >/dev/null; then
					curl -o "$TMPF" $URL
				else
					echo "Can't obtain \"$URL\" because none of the supported tools is available!"
					exit 1
				fi
			fi
		fi
	fi
else
	echo "\"$TMPF\" already exist, skipping download..."
fi

echo "processing oui.txt (\"${TMPF}\")..."

if ! type "gawk" >/dev/null; then
	echo "gawk does not exist"
	exit 1
fi

LANG=C gawk --assign URL=${URL} '
BEGIN {
	NN = 0;
	printf( \
	  "/*\n" \
	  " * Organizationally Unique Identifier list at date %s\n" \
	  " * Automatically generated from %s\n" \
	  " * For Netdiscover\n" \
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
(/^[[:alnum:]]{6}\s+/){
	a=$1
	$1=""
	b = gensub(/[^[:print:]]/, "","g",$0)
	b = gensub(/ \(base 16\)\s*(.+)/,"\\1", "g", b)
	printf("   { \"%s\", \"%s\" },\n", a, b);
	NN++;
}

END {
	printf( \
	  "   { NULL, NULL }\n" \
	  "};\n" \
	  "\n" \
	  "// Total %i items.\n", NN);
}

' ${TMPF} >src/oui.h

if [ $? -ne 0 ]; then
	echo "$JA: $TMPF parsing error !"
	exit 1
else
	echo "All OK"
	ls -oh oui.txt-* src/oui.h
fi
