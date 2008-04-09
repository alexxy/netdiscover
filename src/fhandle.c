/***************************************************************************
 *            fhandle.c
 *
 *  Thu Dec 29 07:04:39 2005
 *  Copyright  2005  Jaime Pealba Estebanez
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
 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "fhandle.h"

/* Read range list from file */
char **fread_list(char *file)
{
   FILE *rl;
   char **rlist;
   char line[100];
   int lcount = 0;
   int trim;

   if ((rl = fopen(file, "r")) == NULL)
      return NULL;

   /* Count lines and rewind, kinda lamme... */
   while (fgets(line, sizeof(line), rl) != NULL)
      lcount++;
   rewind(rl);

   rlist = (char **) malloc (sizeof(char *) * (lcount + 1));
   lcount = 0;

   /* Read lines again and fill double-linked list */
   while (fgets(line, sizeof(line), rl) != NULL) {

      trim = strlen(line) - 1;
      while ( trim >= 0 && ( line[trim] == '\r' || line[trim] == '\n' )) {
         line[trim] = '\0';
         trim--;
      }

      rlist[lcount] = (char *) malloc (sizeof(char) * (strlen(line) + 1));
      snprintf(rlist[lcount], strlen(line) + 1, "%s", line);
      lcount++;
   }

   rlist[lcount] = NULL;
   fclose(rl);
   return rlist;
}
