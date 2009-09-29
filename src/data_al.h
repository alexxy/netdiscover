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

#include <pthread.h>
#include "screen.h"

#ifdef __cplusplus
extern "C"
{
#endif

pthread_mutex_t *data_access;


/* Holds each data type total counters */
struct data_counter {
    unsigned int pakets;   // Total pakets
    unsigned int hosts;    // Total hosts
    unsigned int length;   // Total length
};


/* Holds ethernet headers packet data */
struct p_header {
   unsigned char smac[6];     // Source MAC
   unsigned char dmac[6];     // Destination MAC
   unsigned int length;       // Paket length
};


/* Holds registry data */
struct data_registry {
   struct p_header *header;      // Ethernet data header
   char *sip;                    // Source IP
   char *dip;                    // Destination IP
   char *vendor;                 // MAC vendor
   short type;                   // Paket type
   unsigned int count;           // Total pakets count
   unsigned int tlength;         // Total pakets length
   char focused;                 // Focused (colour / bold)
   struct data_registry *next;   // Next registry
};


/* Holds data abstraction layer for data types */
struct data_al {
   void (*init)(void);                                      // Init data
   void (*beginning_registry)(void);                        // Go to 1st reg
   void (*next_registry)(void);                             // Go to next reg
   struct data_registry *(*current_registry)(void);         // Get current reg
   void (*print_line)(void);                                // Print reg line
   void (*print_header)(int width);                         // Print scr header
   void (*add_registry)(struct data_registry *registry);    // Add new registry
   int  (*hosts_count)(void);                               // Get hosts count
   void (*print_simple_header)();                           // Print smp header
};


extern const struct data_al _data_reply;
extern const struct data_al _data_request;
extern const struct data_al _data_unique;

#ifdef __cplusplus
}
#endif

#endif /* _DATA_AL_H */
