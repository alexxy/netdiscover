/***************************************************************************
 *            screen.h
 *
 *  Tue Jul 12 03:22:19 2005
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


#ifndef _SCREEN_H
#define _SCREEN_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/ioctl.h>

/* ARP types definitions */
#define NARP_REQUEST 1
#define NARP_REPLY 2

/* Screen modes definitions */
#define SMODE_REPLY 0
#define SMODE_REQUEST 1
#define SMODE_HELP 2
#define SMODE_HOST 3

/* Known Hosts highlight color */
//#define KNOWN_COLOR "\33[42;30m%s\33[0m\n"
#define KNOWN_COLOR "\33[1m%s\33[0m\n"

/* Ohh no, more globals */
struct winsize win_sz;
char *current_network;
int parsable_output, continue_listening;


/* Screen functions */
void print_screen();
void fill_screen();
void read_key();
void init_screen();
void sighandler(int);


#ifdef __cplusplus
}
#endif

#endif /* _SCREEN_H */
