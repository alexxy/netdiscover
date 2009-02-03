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
void init_screen()
{
   /* Interface properties */
   scroll = 0;
   smode = SMODE_HOST;

   /* Set interative mode options if no parsable mode */
   if(!parsable_output) {
      /* Set signal handlers */
      signal( SIGCONT, sighandler );
      signal( SIGINT, sighandler );
      signal( SIGKILL, sighandler );
      signal( SIGTERM, sighandler );
      signal( SIGHUP, sighandler );
      signal( SIGABRT, sighandler );

      /* Set console properties to read keys */
      tcgetattr(0,&stored_settings);
      working_settings = stored_settings;

      working_settings.c_lflag &= ~(ICANON|ECHO);
      working_settings.c_cc[VTIME] = 0;
      working_settings.c_cc[VMIN] = 1;
      tcsetattr(0,TCSANOW,&working_settings);
   }
}


/* Handle signals and set terminal */
void sighandler(int signum)
{
   if (parsable_output) {
      exit(0);
   } else {
      if (signum == SIGCONT) {
         tcsetattr(0,TCSANOW,&working_settings);
      } else {
         tcsetattr(0,TCSANOW,&stored_settings);

         signal(SIGINT, SIG_DFL);
         signal(SIGTERM, SIG_DFL);
         pthread_kill(keys, signum);

         exit(0);
      }
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
      scroll -= 1;                           // UP
   else if (ch == 106)
      scroll += 1;                           // DOWN
   else if (ch == 114) {
      smode = SMODE_REQUEST;                 // PRINT REQUEST
      scroll = 0;
   } else if (ch == 97) {
      smode = SMODE_REPLY;                   // PRINT REPLIES
      scroll = 0;
   } else if (ch == 117) {
      smode = SMODE_HOST;                    // PRINT HOSTS
      scroll = 0;
   } else if ((ch == 113) && (smode != SMODE_HELP) )
      sighandler(0);                         // QUIT
   else if ((ch == 113) && (smode == SMODE_HELP) )
      smode = oldmode;                       // CLOSE HELP
   else if ((ch == 104) && (smode != SMODE_HELP)) {
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
   pthread_mutex_lock(data_access);
   fill_screen();
   pthread_mutex_unlock(data_access);
   fprintf( stderr, "\33[J" );
   fflush(stdout);
}


/* Print header line containing scanning and current screen mode */
void print_status_header()
{
   int j;
   char *current_smode = NULL;

   switch (smode) {
      case SMODE_REPLY:
            current_smode = "ARP Reply";
         break;
      case SMODE_REQUEST:
            current_smode = "ARP Request";
         break;
      case SMODE_HOST:
            current_smode = "Unique Hosts";
         break;
      case SMODE_HELP:
            current_smode = "Help";
         break;
   }

   sprintf(line, " Currently scanning: %s   |   Screen View: %s", 
           current_network, current_smode);
   printf("%s", line);

   /* Fill with spaces */
   for (j=strlen(line); j<win_sz.ws_col - 1; j++)
         printf(" ");
   printf("\n");

    /* Print blank line with spaces */
    for (j=0; j<win_sz.ws_col - 1; j++)
         printf(" ");
    printf("\n");
}


/* Fills the screen using white spaces to avoid refresh problems  *
 * not a very smart way, but it works :)                          */
void fill_screen()
{
   const struct data_al *current_data_mode;

   /* Use a data layer depending on current screen mode */
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
      case SMODE_HELP:
            current_data_mode = &_data_unique;
         break;
   }

   /* Print headers */
   print_status_header();
   current_data_mode->print_header(win_sz.ws_col);

   /* Print screen main data */
   if (smode != SMODE_HELP) {

      int x = 0;

      current_data_mode->beginning_registry();
      while (current_data_mode->current_registry() != NULL) {

         if (x >= scroll)
            current_data_mode->print_line();

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

