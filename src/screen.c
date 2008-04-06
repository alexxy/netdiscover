/***************************************************************************
 *            screen.c
 *
 *  Tue Jul 12 03:23:41 2005
 *  Copyright  2005  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 *
 *  Contributors:
 *   Parsable output by Guillaume Pratte <guillaume@guillaumepratte.net>
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
#include "data_al.h"


/* Shity globals */
struct termios stored_settings, working_settings;
extern pthread_t screen, keys, sniffer, injection;


int scroll;
int smode, oldmode;
char line[300], tline[300];
char blank[] = " ";


/* Inits lists with null pointers, sighandlers, etc */
void init_lists()
{
   /* Interface properties */
   scroll = 0;
   smode = 0;

   /* Init data layers */
   _data_reply.init();
   _data_request.init();
   _data_unique.init();

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
   if (signum == SIGCONT) {
      tcsetattr(0,TCSANOW,&working_settings);
   } else {
      tcsetattr(0,TCSANOW,&stored_settings);
      signal(SIGINT, SIG_DFL);
      signal(SIGTERM, SIG_DFL);

      if (!parsable_output)
         pthread_kill(keys, signum);

      exit(0);
   }
}


/* Read input keys */
void read_key()
{
   int ch;
   ch = getchar();

   /* Check for arrow keys */
   if ( ch == 27) {
      ch = getchar();

      if (ch == 91) {
         ch = getchar();

         if (ch == 66)
            ch = 106;
         else if (ch == 65)
            ch = 107;
      }
   }


   /* Key functions */
   if((ch == 107) && (scroll > 0))
      scroll -= 1;                  // UP
   else if (ch == 106)
      scroll += 1;                  // DOWN
   else if (ch == 114) {
      smode = SMODE_REQUEST;        // PRINT REQUEST
      scroll = 0;
   } else if (ch == 97) {
      smode = SMODE_REPLY;          // PRINT REPLIES
      scroll = 0;
   } else if (ch == 117) {
      smode = SMODE_HOST;           // PRINT HOSTS
      scroll = 0;
   } else if ((ch == 113) && (smode != 2) )
      sighandler(0);                         // QUIT
   else if ((ch == 113) && (smode == 2) )
      smode = oldmode;                       // close screen
   else if ((ch == 104) && (smode != 2)) {
      scroll = 0;
      oldmode = smode;                       // PRINT HELP
      smode = SMODE_HELP;
   }
    /* Debug code
    else
    {
        printf("\n\nYou pressed %i\n\n", ch);
        sleep(2);
    } */

   print_screen();
}


/* Clear and fill the screen */
void print_screen()
{
   /* Get Console Size */
   if (ioctl(0, TIOCGWINSZ, &win_sz) < 0) {
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
   const struct data_al *current_data_mode;

   x = 0;	

   sprintf(line, " Currently scanning: %s   |   Our Mac is: %s", 
           current_network, ourmac);
   printf("%s", line);

   /* Fill with spaces */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
         printf(" ");
   printf("\n");

    /* Print blank line with spaces */
    for (j=0; j<win_sz.ws_col - 1; j++)
         printf(" ");
    printf("\n");


   sprintf(line, " 0 Captured ARP Req/Rep packets, from 0 hosts.   Total size: 0" );
           //arprep_count->count, arprep_count->hosts, arprep_count->length);
   printf("%s", line);
	
   /* Fill with spaces */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
         printf(" ");
   printf("\n");
	
   /* Print Header and counters */
   print_header();

   if (smode != SMODE_HELP) {

      current_data_mode = NULL;
      switch (smode) {
         case SMODE_REPLY:
               current_data_mode = &_data_reply;
            break;
         case SMODE_REQUEST:
               current_data_mode = &_data_request;
            break;
         case SMODE_HOST:
               current_data_mode = &_data_unique;
            break;
      }

      current_data_mode->beginning_registry();
      while (current_data_mode->current_registry() != NULL) {
         if (x >= scroll) {
            current_data_mode->print_line();
         }


         current_data_mode->next_registry();
         x++;

         /* Check if end of screen was reached */
         if (x >= ( (win_sz.ws_row + scroll) - 7))
            break;
      }

   } else if(smode == SMODE_HELP) {
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
            "\t |     u: show unique hosts detected            | \n"
            "\t |     q: exit this screen or end               | \n"
            "\t |                                              | \n"
            "\t  ----------------------------------------------  \n");



       for (i=21; i<win_sz.ws_row; i++)
           printf("\n");
   }
}

/* Print Header and counters */
void print_header()
{
	printf(" _____________________________________________________________________________\n");
	
    if (smode == SMODE_REPLY || (oldmode == SMODE_REPLY && smode == SMODE_HELP))
		printf("   IP            At MAC Address      Count  Len   MAC Vendor                   \n");
	else if (smode == SMODE_REQUEST || (oldmode == SMODE_REQUEST && smode == SMODE_HELP))
		printf("   IP            At MAC Address      Requests IP     Count                     \n");
    else if (smode == SMODE_HOST || (oldmode == SMODE_HOST && smode == SMODE_HELP))
        printf("   IP            At MAC Address      Count  Len   MAC Vendor                   \n");
	
    printf(" ----------------------------------------------------------------------------- \n");
}

/*
void print_parsable_screen()
{
	pthread_mutex_lock(listm);
	
	// Header is printed in main.c in parsable_screen_refresh()

    switch (smode)
    {
        case SMODE_REPLY:
            // We initialize our read pointer if there are elements in the list
            if (last_arprep_printed == NULL && first_arprep != NULL)
            {
                last_arprep_printed = first_arprep;
                print_parsable_line(last_arprep_printed);
            }

            // We print what we did not read yet in the list
            if (last_arprep_printed != NULL)
            {
                while (last_arprep_printed->next != NULL)
                {
                    last_arprep_printed = last_arprep_printed->next;
                    print_parsable_line(last_arprep_printed);
                }
            }
        break;
    }

	pthread_mutex_unlock(listm);
} */


/*
void print_parsable_line(struct arp_rep_l *arprep_l)
{
	if (smode == 0)
	{
		// Print each found station trough arp reply
		print_arp_reply_line(last_arprep_printed);
	}
} */


/*
void parsable_output_scan_completed()
{
	char plural = '\0';

	// Sleep a little to give a chance for all replies to come back 
	sleep(0.5);

	pthread_mutex_lock(listm);

	if ( arprep_count->hosts > 1 )
	{
		plural = 's';
	}
	printf("-- Active scan completed, %i IP%c found.", arprep_count->hosts, plural);

	pthread_mutex_unlock(listm);

	if( continue_listening )
	{
		printf(" Continuing to listen passively.\n");
	}
	else
	{
		printf("\n");
		sighandler(0); // QUIT
	}

} */


