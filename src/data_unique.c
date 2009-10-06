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
#include <unistd.h>
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

/* Screen printing buffers */
char line[300], tline[300];
extern char blank[];


/* Initialize required data */
void unique_init()
{
   first_unique = NULL;
   last_unique = NULL;
}

/* Used to beging the iteration between registries */
void unique_beginning_registry() { current_unique = first_unique; }

/* Go to next registry */
void unique_next_registry(void) { current_unique = current_unique->next; }

/* Return current registry mainly to check if its null */
struct data_registry *unique_current_unique(void) { return current_unique; }

/* Return hosts count */
int unique_hosts_count(void) { return unique_count.hosts; }


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
   sprintf(tline, "%02x:%02x:%02x:%02x:%02x:%02x  ",
      current_unique->header->smac[0], current_unique->header->smac[1],
      current_unique->header->smac[2], current_unique->header->smac[3],
      current_unique->header->smac[4], current_unique->header->smac[5]);
   strcat(line, tline);

   /* Count, Length & Vendor */
   sprintf(tline, "%5d %7d  %s", current_unique->count,
      current_unique->tlength, current_unique->vendor );
   strcat(line, tline);

   /* Fill again with spaces and cut the string to fit width */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
      strcat(line, blank);
   string_cutter(line, win_sz.ws_col - 1);


   /* Print host highlighted if its known */
   if (current_unique->focused == 0)
      printf("%s\n", line);
   else
      printf(KNOWN_COLOR, line);
}


/* Add new data to the registry list */
void unique_add_registry(struct data_registry *registry)
{
   int i = 0;
   struct data_registry *new_data;


   if ( first_unique == NULL )
   {
      /* Duplicate this registry, as the pointer is being used by rep/req al */
      new_data = (struct data_registry *) malloc (sizeof(struct data_registry));
      *new_data = *registry;

      unique_count.hosts++;
      search_mac(new_data);

      first_unique = new_data;
      last_unique = new_data;

      /* Set for printing if parsable_output is enabled */
      if (parsable_output)
         current_unique = new_data;

   } else {

      struct data_registry *tmp_registry;
      tmp_registry = first_unique;

      /* Check for dupe packets */
      while ( tmp_registry != NULL && i != 1 ) {

         if ( ( strcmp(tmp_registry->sip, registry->sip) == 0 ) &&
            ( memcmp(tmp_registry->header->smac, registry->header->smac, 6) == 0 ) ) {

            tmp_registry->count++;
            tmp_registry->tlength += registry->header->length;

            /* Not required to print if parsable_output is enabled */
            if (parsable_output)
               current_unique = NULL;

            i = 1;
         }

         tmp_registry = tmp_registry->next;
      }

      /* Add it if isnt dupe */
      if ( i != 1 ) {

         /* Duplicate this registry, as the pointer is being used by rep/req al */
         new_data = (struct data_registry *) malloc (sizeof(struct data_registry));
         *new_data = *registry;

         unique_count.hosts++;
         search_mac(new_data);

         last_unique->next = new_data;
         last_unique = new_data;

         /* Set for printing if parsable_output is enabled */
         if (parsable_output)
            current_unique = new_data;
      }
   }

   unique_count.pakets++;
   unique_count.length += registry->header->length;

   
   if (parsable_output && current_unique != NULL) {
      unique_print_line();
      fflush(stdout);
   }
}

void unique_print_header_sumary(int width)
{
   int j;

   sprintf(line, " %i Captured ARP Req/Rep packets, from %i hosts.   Total size: %i", 
            unique_count.pakets, unique_count.hosts, unique_count.length);
   printf("%s", line);

   /* Fill with spaces */
   for (j=strlen(line); j<width - 1; j++)
         printf(" ");
   printf("\n");
}

void unique_print_simple_header()
{
   printf(" _____________________________________________________________________________\n");
   printf("   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      \n");
   printf(" -----------------------------------------------------------------------------\n");
}

void unique_print_header(int width)
{
   unique_print_header_sumary(width);
   unique_print_simple_header();
}


/* Arp reply data abstraction functions */
const struct data_al _data_unique = {
   unique_init,
   unique_beginning_registry,
   unique_next_registry,
   unique_current_unique,
   unique_print_line,
   unique_print_header,
   unique_add_registry,
   unique_hosts_count,
   unique_print_simple_header
};


/* Extra function to print parseable mode end */
void parseable_scan_end() {

   /* Wait for last replys */
   sleep(1);

   /* Print End */
   printf("\n-- Active scan completed, %i Hosts found.",  unique_count.hosts);

   /* Exit or continue listening */
   if( continue_listening ) {
      printf(" Continuing to listen passively.\n\n");
   } else {
      printf("\n");
      sighandler(0); // QUIT
   }
}
