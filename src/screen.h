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

/* Ohh no, more globals */
struct winsize win_sz;
char *current_network;
int parsable_output, continue_listening;


/* Screen functions */
void print_screen();
void fill_screen();
void print_header();
//void print_parsable_screen();
//void print_parsable_line(struct arp_rep_l *);
//void print_arp_reply_line(struct arp_rep_l *);
//void print_arp_request_line(struct arp_req_l *);
//void print_unique_host_line(struct host_l *);
//void parsable_output_scan_completed();
void read_key();
void sighandler(int);

/* Functions to handle pointer lists */
void init_lists();


#ifdef __cplusplus
}
#endif

#endif /* _SCREEN_H */
