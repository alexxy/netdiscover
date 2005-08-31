/***************************************************************************
 *            screen.h
 *
 *  Tue Jul 12 03:22:19 2005
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


/* Ohh no, more globals */
char *current_network;

 
/* Structs for counters */
struct arp_rep_c {
	unsigned int count;
	unsigned int hosts;
	unsigned int length;
};
 
/* holds headers packet data */
struct p_header {
	unsigned char smac[6];
	unsigned char dmac[6];
	unsigned int length;
};
 

/* holds arp requests packet data */
struct arp_req_l {
	struct p_header *header;
	char *sip;
	char *dip;
	unsigned int count;
	struct arp_req_l *next;
};


/* holds arp replys packet data */
struct arp_rep_l {
	struct p_header *header;
	char *sip;
	char *dip;
	char *vendor;
	unsigned int count;
	struct arp_rep_l *next;
};



/* Screen functions */
void print_screen();
void fill_screen();

/* Lists functions */
void init_lists();
void arprep_add(struct arp_rep_l *);
