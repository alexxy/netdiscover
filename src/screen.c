/***************************************************************************
 *            screen.c
 *
 *  Tue Jul 12 03:23:41 2005
 *  Copyright  2005  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
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
 
 /*
  *  Thanks to Christophe Devine, aircrack creator, who gave me the
  *  inspiration to make this screen interface. You can see his site
  *  here http://www.cr0.net:8040/code/network/
  */
 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "screen.h"
#include "misc.h"
#include "ifaces.h"

struct arp_req_l *first_arpreq, *last_arpreq;
struct arp_rep_l *first_arprep, *last_arprep;
struct arp_rep_c *arprep_count;

/* Clear and fill the screen */
void print_screen()
{
	fprintf( stderr, "\33[1;1H" );
	fill_screen();
	fprintf( stderr, "\33[J" );
	fflush(stdout);
}


/* Fills the screen */
void fill_screen()
{
	
	struct arp_rep_l *arprep_l;
	arprep_l = first_arprep;
	
	
	printf("Currently scanning: %s    |   "
				"Our Mac is: %s       \n"
				"                                        \n",
				current_network, ourmac);
	
	/* Print Captured ARP Replys */
	printf(" %d Captured ARP Reply packets, from %d hosts.   Total size: %d\n"
				" ______________________________________________________________________________\n"
				"|  IP            At MAC Address      Count  Length   MAC Vendor                |\n"
				" ------------------------------------------------------------------------------\n",
				arprep_count->count, arprep_count->hosts, arprep_count->length );
	
	while( arprep_l != NULL )
	{
		printf("  %s\t %s\t%d     %d    %s\n", arprep_l->sip, 
					arprep_l->header->smac, arprep_l->count, 
					arprep_l->header->length, arprep_l->vendor );
		
		arprep_l = arprep_l->next;
	}
	
}


/* Inits lists with null pointers, etc */
void init_lists()
{
	/* ARP Requests */
	first_arpreq = (struct arp_req_l *) NULL;
	last_arpreq = (struct arp_req_l *) NULL;

	/* ARP Replys */
	first_arprep = (struct arp_rep_l *) NULL;
	last_arprep = (struct arp_rep_l *) NULL;
		
	/* ARP Replys counters */
	arprep_count = (struct arp_rep_c *) malloc (sizeof(struct arp_rep_c));
	arprep_count->count = 0;
	arprep_count->hosts = 0;
	arprep_count->length = 0;
}


/* Adds ARP packet data to the list */
void arprep_add(struct arp_rep_l *new)
{	
	int i = 0;
	
	if ( first_arprep == NULL )
	{
		arprep_count->hosts += 1;
		arprep_count->count += 1;
		arprep_count->length += new->header->length;
		new->vendor = search_vendor(new->header->smac);
		
		first_arprep = new;
		last_arprep = new;
	}
	else
	{
		struct arp_rep_l *arprep_l;
		arprep_l = first_arprep;
		
		/* Check for dupe packets */
		while ( arprep_l != NULL && i != 1 )
		{
			if ( ( strcmp(arprep_l->sip, new->sip) == 0 ) 
					&& ( strcmp(arprep_l->header->smac, new->header->smac) == 0 ) )
			{
				arprep_l->count += 1;
				arprep_l->header->length += new->header->length;
				
				i = 1;
			}
			
			arprep_l = arprep_l->next;
		}
		
		/* Add it if isnt dupe */
		if ( i != 1 )
		{
			arprep_count->hosts += 1;
			new->vendor = search_vendor(new->header->smac);
			
			last_arprep->next = new;
			last_arprep = new;
		}
		
		arprep_count->count += 1;
		arprep_count->length += new->header->length;
	}
}
