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
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "misc.h"
#include "oui.h"


char *search_vendor(char *mac)
{
	char *tmac;
	int i = 0;
	
	tmac = (char *) malloc (sizeof(char) * 6);
	
	sprintf(tmac, "%c%c%c%c%c%c",
		toupper(mac[0]), toupper(mac[1]), toupper(mac[3]),
		toupper(mac[4]), toupper(mac[6]), toupper(mac[7]));
	
	//printf ("prefijo %s\n", tmac);
	//exit(1);
	
	for (i=0;i<8436;i++)
	{
		if (strcmp(oui_table[i].prefix, tmac) == 0)
			return oui_table[i].vendor;
	}
	
	return "Unknown vendor";
}
