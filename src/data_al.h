/***************************************************************************
 *            data_al.h
 *
 *  Sat Apr  5 09:36:32 CEST 2008
 *  Copyright  2008  Jaime Penalba Estebanez
 *  jpenalbae@gmail.com
 *
 *  Data abstraction layer
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

#ifndef _DATA_AL_H
#define _DATA_AL_H

#include "screen.h"

#ifdef __cplusplus
extern "C"
{
#endif


struct data_counter {
    unsigned int pakets;
    unsigned int hosts;
    unsigned int length;
};


/* holds headers packet data */
struct p_header {
   unsigned char smac[6];
   unsigned char dmac[6];
   unsigned int length;
};


struct data_registry {
   struct p_header *header;
   char *sip;
   char *dip;
   char *vendor;
   short type;
   unsigned int count;
   struct data_registry *next;
};


struct data_al {
   void (*init)(void);
   void (*beginning_registry)(void);
   void (*next_registry)(void);
   struct data_registry *(*current_registry)(void);
   void (*print_parseable_line)(struct data_registry *registry);
   void (*print_line)(void);
   void (*add_registry)(struct data_registry *registry);
};


extern const struct data_al _data_reply;
extern const struct data_al _data_request;
extern const struct data_al _data_unique;

#ifdef __cplusplus
}
#endif

#endif /* _DATA_AL_H */
