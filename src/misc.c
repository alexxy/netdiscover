/***************************************************************************
 *            misc.c
 *
 *  Thu Jul 21 03:20:02 2005
 *  Copyright  2005  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/ether.h>
#include "ifaces.h"
#include "misc.h"
#include "oui.h"


struct ether_addr **split_mac_list(char *string)
{
   int x;
   int count = 0;
   char *aux;
   struct ether_addr **macs;
   const char delimiters[] = ",";

   /* Count number of items in the string  */
   for (x=0; x<strlen(string); x++)
       if (string[x] == delimiters[0]) count++;
   
   macs = (struct ether_addr **) malloc (count + 2);
   
   /* Fill the ignore_macs list */
   x = 0;
   aux = strtok (string, delimiters);
   while (aux != NULL) {
       macs[x] = ether_aton(aux);
       aux = strtok (NULL, delimiters);
       x++;
   }
   macs[x] = NULL;

   return macs;
}

char *search_vendor(unsigned char mac[6])
{
	char tmac[7];
	int i = 0;
	
	sprintf(tmac, "%02x%02x%02x", mac[0], mac[1], mac[2]);

	/* Convert mac prefix to upper */
	for (i=0; i<6; i++)
	   tmac[i] = toupper(tmac[i]);
	
	i = 0;

	while (oui_table[i].prefix != NULL)
	{
		if (strcmp(oui_table[i].prefix, tmac) == 0)
			return oui_table[i].vendor;
        	i++;
	}
	
	return "Unknown vendor";
}
