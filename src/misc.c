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
#include "fhandle.h"
#include "misc.h"
#include "oui.h"


/* optional table/list of MAC addresses of known hosts */
char **known_mac_table;


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



int load_known_mac_table(char *file)
{
    int i, j, len;

    /* assume: list of known host is rather small so          *
     * fread_list() and the simple structure should be enough */
    known_mac_table = fread_list(file);
    /* ERROR: unable to read the file */
    if (known_mac_table == NULL) return -1;

    /* debug */
    printf("Known MACs table loaded.\n");

    i = 0;

   while (known_mac_table[i] != NULL) {

      len = strlen(known_mac_table[i]);

      if (len < 12+2) { /* MAC number + '/0' + '!' = 12+2 chars */
         printf("ERROR: no full MAC given in the file! (%s)\n",
                 known_mac_table[i]);
         sleep(5);
         /* protection - read what is possible */
         if (len > 0) {
            known_mac_table[i][0] = '?';
            /* WARNING */
            i++; continue;
          } else {
            /* finish parsing, skip all others lines - ERROR */
            break;
          }
      }

      /* Convert mac to upper */
      for (j=0; j<12; j++)
         known_mac_table[i][j] = toupper(known_mac_table[i][j]);


      /* convert all spaces and tabulator after MAC address into '\0' */
      for (j = 12; j < len; j++)
      {
         if ((known_mac_table[i][j] == ' ') || (known_mac_table[i][j] == '\t'))
            known_mac_table[i][j] = '\0';
         else
            break;	// first char of hostname
      }

      if (j >= len) {
          printf("WARNING: no host name given in the file! (%s)\n",
                  known_mac_table[i]);
          sleep(5);
          /* protection */
          known_mac_table[i][13] = '!';
      }

      /* next line */
      i++;
   }	// while

    printf("Parsing known MACs table completed.\n");
    return 0;
}

char *get_known_mac_hostname(char *mac_hostname)
{
	if (strlen(mac_hostname) != 12) {
	    /* error in MACs table content */
	    return NULL;
	}

	/* skip MAC and all '\0' */
	mac_hostname += 12;
	while (*mac_hostname == '\0') mac_hostname++;

	return mac_hostname;
}


/* find out known host name */
char *search_known_mac(unsigned char mac[6])
{
	char tmac[13];
	int i;

	/* protection */
	if (known_mac_table == NULL)
      return NULL;

	sprintf(tmac, "%02x%02x%02x%02x%02x%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	/* Convert mac to upper */
	for (i=0; i<12; i++)
	   tmac[i] = toupper(tmac[i]);

	i = 0;

	while (known_mac_table[i] != NULL) {
      
		if (strcmp(known_mac_table[i]/*separated MAC*/, tmac) == 0)
			return get_known_mac_hostname(known_mac_table[i]);
      i++;
	}

	return NULL;
}


/* First try find out known host name, otherwise use standard vendor */
void search_mac(struct data_registry *registry)
{
   registry->vendor = search_known_mac(registry->header->smac);

   if (registry->vendor == NULL) {
      registry->vendor = search_vendor(registry->header->smac);
      registry->focused = 0;	/* unidentified host, vendor used */
    } else {
      registry->focused = 1; /* identified host, hostname used */
    }
}

