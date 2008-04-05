/***************************************************************************
 *            data_unique.c
 *
 *  Sat Apr  5 09:36:32 CEST 2008
 *  Copyright  2008  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 *
 *  Data abstraction layer part for unique hosts
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
struct data_registry *first_unique, *last_unique;

/* Pointer to handle list */
struct data_registry *current_unique;

/* Registry data counter */
struct data_counter unique_count;

/* Mutexes for accessing lists */
pthread_mutex_t *unique_mutex;

/* Screen printing buffers */
char line[300], tline[300];
extern char blank[];


/* Initialize required data */
void unique_init()
{
   first_unique = NULL;
   last_unique = NULL;

   /* Mutex for list access */
   unique_mutex =(pthread_mutex_t *)malloc(sizeof (pthread_mutex_t));
   pthread_mutex_init(unique_mutex, NULL);
}

/* Used to beging the iteration between registries */
void unique_beginning_registry() { current_unique = first_unique; }

/* Go to next registry */
void unique_next_registry(void) { current_unique = current_unique->next; }

/* Return current registry mainly to check if its null */
struct data_registry *unique_current_unique(void) { return current_unique; }

/* Not required in this mode */
void unique_print_parseable_line(struct data_registry *registry) { /* NULL */ }


/* Print current registry line (for interactive mode) */
void unique_print_line()
{
   int j;

   sprintf(line, " ");
   sprintf(tline, " ");

   /* Set IP */
   sprintf(tline, "%s ", current_unique->sip);
   strcat(line, tline);

   /* Fill with spaces */
   for (j=strlen(line); j<17; j++)
      strcat(line, blank);

   /* IP & MAC */
   sprintf(tline, "%02x:%02x:%02x:%02x:%02x:%02x    ",
      current_unique->header->smac[0], current_unique->header->smac[1],
      current_unique->header->smac[2], current_unique->header->smac[3],
      current_unique->header->smac[4], current_unique->header->smac[5]);
   strcat(line, tline);

   /* Count, Length & Vendor */
   sprintf(tline, "%02d    %03d   %s", current_unique->count, 
      current_unique->header->length, current_unique->vendor );
   strcat(line, tline);

   /* Fill again with spaces */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
      strcat(line, blank);

   printf("%s\n", line);
}


/* Add new data to the registry list */
void unique_add_registry(struct data_registry *registry)
{
   int i = 0;

   pthread_mutex_lock(unique_mutex);

   if ( first_unique == NULL )
   {
      unique_count.hosts++;
      registry->vendor = search_vendor(registry->header->smac);

      first_unique = registry;
      last_unique = registry;

   } else {

      struct data_registry *tmp_registry;
      tmp_registry = first_unique;

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

         unique_count.hosts++;
         registry->vendor = search_vendor(registry->header->smac);

         last_unique->next = registry;
         last_unique = registry;
      }
   }

   unique_count.pakets++;
   unique_count.length += registry->header->length;

   pthread_mutex_unlock(unique_mutex);
}


/* Arp reply data abstraction functions */
const struct data_al _data_unique = {
   unique_init,
   unique_beginning_registry,
   unique_next_registry,
   unique_current_unique,
   unique_print_parseable_line,
   unique_print_line,
   unique_add_registry
};
