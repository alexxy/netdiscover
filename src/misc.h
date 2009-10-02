/***************************************************************************
 *            misc.h
 *
 *  Thu Jul 21 03:19:30 2005
 *  Copyright  2005  Jaime Penalba Estebanez
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
 
 
#ifndef _MISC_H
#define _MISC_H

#include "data_al.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* Functions */
    char *search_vendor(unsigned char[6]);
    void string_cutter(char *, int);
    int load_known_mac_table(char *);
    void search_mac(struct data_registry *);
	
#ifdef __cplusplus
}
#endif

#endif /* _MISC_H */
