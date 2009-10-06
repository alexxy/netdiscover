/***************************************************************************
 *            data_reply.c
 *
 *  Sat Apr  5 09:36:32 CEST 2008
 *  Copyright  2008  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 *
 *  Data abstraction layer part for arp replys
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
struct data_registry *first_reply, *last_reply;

/* Pointer to handle list */
struct data_registry *current_reply;

/* Registry data counter */
struct data_counter reply_count;

/* Screen printing buffers */
char line[300], tline[300];
extern char blank[];


/* Initialize required data */
void reply_init()
{
   first_reply = NULL;
   last_reply = NULL;
}

/* Used to beging the iteration between registries */
void reply_beginning_registry() { current_reply = first_reply; }

/* Go to next registry */
void reply_next_registry(void) { current_reply = current_reply->next; }

/* Return current registry mainly to check if its null */
struct data_registry *reply_current_reply(void) { return current_reply; }

/* Return hosts count */
int reply_hosts_count(void) { return reply_count.hosts; }



/* Print current registry line (for interactive mode) */
void reply_print_line()
{
   int j;

   sprintf(line, " ");
   sprintf(tline, " ");

   /* Set IP */
   sprintf(tline, "%s ", current_reply->sip);
   strcat(line, tline);

   /* Fill with spaces */
   for (j=strlen(line); j<17; j++)
      strcat(line, blank);

   /* IP & MAC */
   sprintf(tline, "%02x:%02x:%02x:%02x:%02x:%02x  ",
      current_reply->header->smac[0], current_reply->header->smac[1],
      current_reply->header->smac[2], current_reply->header->smac[3],
      current_reply->header->smac[4], current_reply->header->smac[5]);
   strcat(line, tline);

   /* Count, Length & Vendor */
   sprintf(tline, "%5d %7d  %s", current_reply->count,
      current_reply->header->length, current_reply->vendor );
   strcat(line, tline);


   /* Fill again with spaces and cut the string to fit width */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
      strcat(line, blank);
   string_cutter(line, win_sz.ws_col - 1 );

   /* Print host highlighted if its known */
   if (current_reply->focused == 0)
      printf("%s\n", line);
   else
      printf(KNOWN_COLOR, line);
}


/* Add new data to the registry list */
void reply_add_registry(struct data_registry *registry)
{
   int i = 0;

   _data_unique.add_registry(registry);

   if ( first_reply == NULL )
   {
      reply_count.hosts++;
      search_mac(registry);

      first_reply = registry;
      last_reply = registry;

   } else {

      struct data_registry *tmp_registry;
      tmp_registry = first_reply;

      /* Check for dupe packets */
      while ( tmp_registry != NULL && i != 1 ) {

         if ( ( strcmp(tmp_registry->sip, registry->sip) == 0 ) &&
            ( memcmp(tmp_registry->header->smac, registry->header->smac, 6) == 0 ) ) {

            tmp_registry->count++;
            tmp_registry->header->length += registry->header->length;

            i = 1;
         }

         tmp_registry = tmp_registry->next;
      }

      /* Add it if isnt dupe */
      if ( i != 1 ) {

         reply_count.hosts++;
         search_mac(registry);

         last_reply->next = registry;
         last_reply = registry;
      }
   }

   reply_count.pakets++;
   reply_count.length += registry->header->length;

}


void reply_print_header_sumary(int width)
{
   int j;

   sprintf(line, " %i Captured ARP Reply packets, from %i hosts.   Total size: %i", 
            reply_count.pakets, reply_count.hosts, reply_count.length);
   printf("%s", line);

   /* Fill with spaces */
   for (j=strlen(line); j<width - 1; j++)
         printf(" ");
   printf("\n");
}

void reply_print_header(int width)
{
   reply_print_header_sumary(width);
   printf(" _____________________________________________________________________________\n");
   printf("   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      \n");
   printf(" -----------------------------------------------------------------------------\n");
}


/* Arp reply data abstraction functions */
const struct data_al _data_reply = {
   reply_init,
   reply_beginning_registry,
   reply_next_registry,
   reply_current_reply,
   reply_print_line,
   reply_print_header,
   reply_add_registry,
   reply_hosts_count
};
