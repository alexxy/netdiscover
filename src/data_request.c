/***************************************************************************
 *            data_request.c
 *
 *  Sat Apr  5 09:36:32 CEST 2008
 *  Copyright  2008  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 *
 *  Data abstraction layer part for arp request
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "misc.h"
#include "data_al.h"


/* Pointers to hold list data */
struct data_registry *request_first, *request_last;

/* Pointer to handle list */
struct data_registry *request_current;

/* Registry data counter */
struct data_counter request_count;

/* Screen printing buffers */
char line[300], tline[300];
extern char blank[];


/* Initialize required data */
void request_init()
{
   request_first = NULL;
   request_last = NULL;
}

/* Used to beging the iteration between registries */
void request_beginning_registry() { request_current = request_first; }

/* Go to next registry */
void request_next_registry(void) { request_current = request_current->next; }

/* Return current registry mainly to check if its null */
struct data_registry *request_current_registry(void) {return request_current;}

/* Return hosts count */
int request_hosts_count(void) { return request_count.hosts; }


/* Print current registry line (for interactive mode) */
void request_print_line()
{
   int j;

   sprintf(line, " ");
   sprintf(tline, " ");

   /* Get source IP */
   sprintf(tline, "%s ", request_current->sip);
   strcat(line, tline);

   /* Fill with spaces */
   for (j=strlen(line); j<17; j++)
      strcat(line, blank);

   /* Get source MAC */
   sprintf(tline, "%02x:%02x:%02x:%02x:%02x:%02x   ",
      request_current->header->smac[0], request_current->header->smac[1],
      request_current->header->smac[2], request_current->header->smac[3],
      request_current->header->smac[4], request_current->header->smac[5]);
   strcat(line, tline);

   /* Get destination IP */
   sprintf(tline, "%s", request_current->dip);
   strcat(line, tline);

   /* Fill with spaces */
   for (j=strlen(line); j<54; j++)
      strcat(line, blank);

   /* Count, Length & Vendor */
   sprintf(tline, "%5d", request_current->count);
   strcat(line, tline);

   /* Fill again with spaces and cut the string to fit width */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
      strcat(line, blank);
   string_cutter(line, win_sz.ws_col - 1);

   /* Print host highlighted if its known */
   if (request_current->focused == 0)
      printf("%s\n", line);
   else
      printf(KNOWN_COLOR, line);
}


/* Add new data to the registry list */
void request_add_registry(struct data_registry *registry)
{
   int i = 0;

   _data_unique.add_registry(registry);

   if ( request_first == NULL )
   {
      request_count.hosts++;
      search_mac(registry);

      request_first = registry;
      request_last = registry;

   } else {

      struct data_registry *tmp_request;
      tmp_request = request_first;

      /* Check for dupe packets */
      while ( tmp_request != NULL && i != 1 ) {

         if ( ( strcmp(tmp_request->sip, registry->sip) == 0 ) &&
            ( strcmp(tmp_request->dip, registry->dip) == 0 ) &&
            ( memcmp(tmp_request->header->smac, registry->header->smac, 6) == 0 ) ) {

            tmp_request->count++;
            tmp_request->header->length += registry->header->length;

            i = 1;
         }

         tmp_request = tmp_request->next;
      }

      /* Add it if isnt dupe */
      if ( i != 1 ) {

         request_count.hosts++;
         search_mac(registry);

         request_last->next = registry;
         request_last = registry;
      }
   }

   request_count.pakets++;
   request_count.length += registry->header->length;

}


void request_print_header_sumary(int width)
{
   int j;

   sprintf(line, " %i Captured ARP Request packets, from %i hosts.   Total size: %i", 
           request_count.pakets, request_count.hosts, request_count.length);
   printf("%s", line);

   /* Fill with spaces */
   for (j=strlen(line); j<width - 1; j++)
         printf(" ");
   printf("\n");
}

void request_print_header(int width)
{
   request_print_header_sumary(width);
   printf(" _____________________________________________________________________________\n");
   printf("   IP            At MAC Address      Requests IP      Count                   \n");
   printf(" -----------------------------------------------------------------------------\n");
}


/* Arp reply data abstraction functions */
const struct data_al _data_request = {
   request_init,
   request_beginning_registry,
   request_next_registry,
   request_current_registry,
   request_print_line,
   request_print_header,
   request_add_registry,
   request_hosts_count
};
