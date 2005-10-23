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
#include <signal.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "screen.h"
#include "misc.h"
#include "ifaces.h"


/* Shity globals */
struct termios stored_settings, working_settings;
struct arp_rep_l *first_arprep, *last_arprep;
struct arp_rep_l *first_arpreq, *last_arpreq;
struct arp_rep_c *arprep_count;
struct winsize win_sz;
pthread_mutex_t *listm;

int scroll;
int smode, oldmode;
char line[300], tline[300];


/* Inits lists with null pointers, sighandlers, etc */
void init_lists()
{
	scroll = 0;
	smode = 0;
	
	/* Mutex for list access */
	listm =(pthread_mutex_t *)malloc(sizeof (pthread_mutex_t));
	pthread_mutex_init(listm, NULL);
	
   /* ARP reply packets lists */
   first_arprep = (struct arp_rep_l *) NULL;
   last_arprep = (struct arp_rep_l *) NULL;

   /* ARP request packets lists */
   first_arpreq = (struct arp_rep_l *) NULL;
   last_arpreq = (struct arp_rep_l *) NULL;
	
	/* ARP counters */
	arprep_count = (struct arp_rep_c *) malloc (sizeof(struct arp_rep_c));
	arprep_count->count = 0;
	arprep_count->hosts = 0;
	arprep_count->length = 0;
	
	/* Set signal handlers */
	signal( SIGINT,   sighandler );
   signal( SIGKILL,   sighandler );
   signal( SIGTERM,   sighandler );
   signal( SIGHUP,   sighandler );
   signal( SIGABRT,   sighandler );
   signal( SIGCONT,   sighandler );

	/* Set console properties to read keys */
   tcgetattr(0,&stored_settings);
   working_settings = stored_settings;

	working_settings.c_lflag &= ~(ICANON|ECHO);
   working_settings.c_cc[VTIME] = 0;
   working_settings.c_cc[VMIN] = 1;

   tcsetattr(0,TCSANOW,&working_settings);
}


/* Handle signals and set terminal */
void sighandler(int signum)
{
	if (signum == SIGCONT)
    {
        tcsetattr(0,TCSANOW,&working_settings);
    }
    else
    {
        tcsetattr(0,TCSANOW,&stored_settings);
        exit(0);
    }
}


/* Read input keys */
void read_key()
{
    int ch;
    ch = getchar();

    /* Check for arrow keys */
    if ( ch == 27)
    {
        ch = getchar();
		 
        if (ch == 91)
        {
            ch = getchar();

            if (ch == 66)
                ch = 106;
            else if (ch == 65)
                ch = 107;
        }
    }
    

    /* Key functions */
	 if((ch == 107) && (scroll > 0))
    	scroll -= 1;		// UP
    else if ((ch == 106)&&(scroll < (arprep_count->hosts - win_sz.ws_row + 7)))
		 scroll += 1;		// DOWN
	 else if (ch == 114)
    {
		 smode = 1;	// PRINT REQUEST
       scroll = 0;
    }
	 else if (ch == 97)
    {
		 smode = 0;	// PRINT ALL
       scroll = 0;
    }
	 else if ((ch == 113) && (smode != 2) )
		 sighandler(0);	// QUIT
    else if ((ch == 113) && (smode == 2) )
		 smode = oldmode;	// close screen
    else if (ch == 104)
    {
       scroll = 0;
		 oldmode = smode;	// PRINT HELP
       smode = 2;
    }
	 
	 print_screen();
}


/* Clear and fill the screen */
void print_screen()
{
	/* Get Console Size */
   if (ioctl(0, TIOCGWINSZ, &win_sz) < 0)
   {
   	win_sz.ws_row = 24;
      win_sz.ws_col = 80;
   }
	 
	/* Flush and print screen */
	fprintf( stderr, "\33[1;1H" );
	fill_screen();
	fprintf( stderr, "\33[J" );
	fflush(stdout);
}


/* Fills the screen using white spaces to avoid refresh problems  *
 * not a very smart way, but it works :)                          */
void fill_screen()
{
   int x, j;
   struct arp_rep_l *arprep_l;
   char blank[] = " ";
	
   x = 0;
   
   pthread_mutex_lock(listm);	
	
   sprintf(line, " Currently scanning: %s   |   Our Mac is: %s - %i", 
           current_network, ourmac, scroll);
   printf("%s", line);
	
   /* Fill with spaces */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
         printf(" ");
   printf("\n");
	
	/* Print blank line with spaces */
   for (j=0; j<win_sz.ws_col - 1; j++)
         printf(" ");
   printf("\n");


   sprintf(line, " %d Captured ARP Req/Rep packets, from %d hosts.   Total size: %d", 
           arprep_count->count, arprep_count->hosts, arprep_count->length);
   printf("%s", line);
	
   /* Fill with spaces */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
         printf(" ");
   printf("\n");
	
	
   /* Print Header and counters */
   printf(" _____________________________________________________________________________\n");
   if (smode == 0 || (oldmode == 0 && smode == 2))
   	printf("   IP            At MAC Address      Count  Len   MAC Vendor                   \n");
   else if (smode == 1 || (oldmode == 1 && smode == 2))
   	printf("   IP            At MAC Address      Requests IP     Count                     \n");
   printf(" ----------------------------------------------------------------------------- \n");


   /* Print each found station trough arp reply */
   if (smode == 0)
   {
      arprep_l = first_arprep;
      
      while(arprep_l != NULL)
      {
         if (x >= scroll)
         {
            sprintf(line, " ");
            sprintf(tline, " ");
            
            /* Set IP */
            sprintf(tline, "%s ", arprep_l->sip);
            strcat(line, tline);
            
            /* Fill with spaces */
            for (j=strlen(line); j<17; j++)
               strcat(line, blank);
            
            /* IP & MAC */
            sprintf(tline, "%02x:%02x:%02x:%02x:%02x:%02x    ",
               arprep_l->header->smac[0], arprep_l->header->smac[1],
               arprep_l->header->smac[2], arprep_l->header->smac[3],
               arprep_l->header->smac[4], arprep_l->header->smac[5]);
            strcat(line, tline);
            
            /* Count, Length & Vendor */
            sprintf(tline, "%02d    %03d   %s", arprep_l->count, 
                    arprep_l->header->length, arprep_l->vendor );
            strcat(line, tline);
            
            /* Fill again with spaces */
            for (j=strlen(line); j<win_sz.ws_col - 1; j++)
               strcat(line, blank);
            
            printf("%s\n", line);
         }
         
         arprep_l = arprep_l->next;
         x += 1;
      
         /* Check if end of screen was reached */
         if (x >= ( (win_sz.ws_row + scroll) - 7))
            break;
      }
      
   } /* Print only arp request */
   else if (smode == 1)
   {
      arprep_l = first_arpreq;
      
      while(arprep_l != NULL)
      {
         if (x >= scroll)
         {  
            sprintf(line, " ");
            sprintf(tline, " ");
            
            /* Get source IP */
            sprintf(tline, "%s ", arprep_l->sip);
            strcat(line, tline);
            
            /* Fill with spaces */
            for (j=strlen(line); j<17; j++)
               strcat(line, blank);
            
            /* Get source MAC */
            sprintf(tline, "%02x:%02x:%02x:%02x:%02x:%02x   ",
               arprep_l->header->smac[0], arprep_l->header->smac[1],
               arprep_l->header->smac[2], arprep_l->header->smac[3],
               arprep_l->header->smac[4], arprep_l->header->smac[5]);
            strcat(line, tline);
            
            /* Get destination IP */
            sprintf(tline, "%s", arprep_l->dip);
            strcat(line, tline);
            
            /* Fill with spaces */
            for (j=strlen(line); j<54; j++)
               strcat(line, blank);
            
            /* Count, Length & Vendor */
            sprintf(tline, "%02d", arprep_l->count);
            strcat(line, tline);
            
            /* Fill again with spaces */
            for (j=strlen(line); j<win_sz.ws_col - 1; j++)
               strcat(line, blank);
            
            printf("%s\n", line);
         }
         
         arprep_l = arprep_l->next;
         x += 1;
      
         /* Check if end of screen was reached */
         if (x >= ( (win_sz.ws_row + scroll) - 7))
            break;
      }
   }
   else if(smode == 2)
   {
      int i;
       
       printf("\n"
               "\t  ______________________________________________  \n"
               "\t |                                              | \n"
               "\t |    \33[1mHelp screen\33[0m                               | \n"
               "\t |                                              | \n"
               "\t |     h: show this help screen                 | \n"
               "\t |     j: scroll down (or down arrow)           | \n"
               "\t |     k: scroll up   (or up arrow)             | \n"
               "\t |     a: show arp replys list                  | \n"
               "\t |     r: show arp requests list                | \n"
               "\t |     q: exit this screen or end               | \n"
               "\t |                                              | \n"
               "\t  ----------------------------------------------  \n");
   
       
       
       for (i=20; i<win_sz.ws_row; i++)
           printf("\n");
   }

   pthread_mutex_unlock(listm);
}


/* Adds ARP reply packet data to the list */
void arprep_add(struct arp_rep_l *new)
{	
	int i = 0;
	
	pthread_mutex_lock(listm);
	
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
			if ( ( strcmp(arprep_l->sip, new->sip) == 0 ) &&
				( memcmp(arprep_l->header->smac, new->header->smac, 6) == 0 ) )
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
	
	pthread_mutex_unlock(listm);
}


/* Adds ARP request packet data to the list */
void arpreq_add(struct arp_rep_l *new)
{	
	int i = 0;
	
	pthread_mutex_lock(listm);
	
	if ( first_arpreq == NULL )
	{
		arprep_count->hosts += 1;
		arprep_count->count += 1;
		arprep_count->length += new->header->length;
		new->vendor = search_vendor(new->header->smac);
		
		first_arpreq = new;
		last_arpreq = new;
	}
	else
	{
		struct arp_rep_l *arp_l;
		arp_l = first_arpreq;
		
		/* Check for dupe packets */
		while ( arp_l != NULL && i != 1 )
		{
			if ( ( strcmp(arp_l->sip, new->sip) == 0 ) &&
				( memcmp(arp_l->header->smac, new->header->smac, 6) == 0 ) &&
            ( strcmp(arp_l->dip, new->dip) == 0 ) )
			{
				arp_l->count += 1;
				arp_l->header->length += new->header->length;
				
				i = 1;
			}
			
			arp_l = arp_l->next;
		}
		
		/* Add it if isnt dupe */
		if ( i != 1 )
		{
			arprep_count->hosts += 1;
			new->vendor = search_vendor(new->header->smac);
			
			last_arpreq->next = new;
			last_arpreq = new;
		}
		
		arprep_count->count += 1;
		arprep_count->length += new->header->length;
	}
	
	pthread_mutex_unlock(listm);
}
