/***************************************************************************
 *            ifaces.c
 *
 *  Mon Jun 27 04:56:42 2005
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


#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <libnet.h>
#include "screen.h"
#include "ifaces.h"


#define ARP_REPLY "\x00\x02"
#define ARP_REQUEST "\x00\x01"

#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#endif


/* Threads data structure */
struct t_data {
	char *disp;
	char *sip;
	int autos;
};


/* Shitty globals */
libnet_t *libnet;
unsigned char smac[ETH_ALEN];
struct p_header *temp_header;


/* Start Sniffing on given iface */
void *start_sniffer(void *args)
{
	pcap_t *descr;
	struct bpf_program fp;	
	struct t_data *datos; 

	datos = (struct t_data *)args;
		
	/* Open interface */
	descr = pcap_open_live(datos->disp, BUFSIZ, 1, PCAP_TOUT, errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}
	
	/* Set pcap filter for arp only */
	pcap_compile(descr, &fp, "arp", 0, 0);
	pcap_setfilter(descr, &fp);
	
	/* Start loop for packet capture */
	pcap_loop(descr, -1, (pcap_handler)process_packet, NULL);

	return NULL;
}


/* Handle packets recived from pcap_loop */
void process_packet(u_char *args, struct pcap_pkthdr* pkthdr,
                    const u_char* packet)
{
    struct p_header *new_header;
    new_header = (struct p_header *) malloc (sizeof(struct p_header));

    /* Get packet ethernet header data and fill struct */
    memcpy(new_header->dmac, packet, 6);         /* dest mac    */
    memcpy(new_header->smac, packet + 6, 6);     /* src mac     */
    new_header->length = pkthdr->len;            /* Packet size */

    /* Discard packets with our mac as source */
    if (memcmp(new_header->smac, smac, 6) != 0)
    {
        unsigned char type[2];
        memcpy(type, packet + 20, 2);

        /* Check if its ARP request or reply, and add it to list */
        if (memcmp(type, ARP_REPLY, 2) == 0)
        {
            struct arp_rep_l *new_arprep_l;
            new_arprep_l = (struct arp_rep_l *) malloc (sizeof(struct arp_rep_l));

            /* Populate basic arp info */
            new_arprep_l->header = new_header;  /* Add header */
            new_arprep_l->type = 2;             /* Arp Type */

            process_arp_header( (void *)new_arprep_l, 2, packet);
            arprep_add(new_arprep_l);
        }
        else if (memcmp(type, ARP_REQUEST, 2) == 0)
        {
            struct arp_req_l *new_arpreq_l;
            new_arpreq_l = (struct arp_req_l *) malloc (sizeof(struct arp_req_l));

            /* Populate basic arp info */
            new_arpreq_l->header = new_header;  /* Add header */
            new_arpreq_l->type = 1;             /* Arp Type */

            process_arp_header( (void *)new_arpreq_l, 1, packet);
            arpreq_add(new_arpreq_l);
        }
    }
}

/* Handle arp packet header */
void process_arp_header(void *arp, u_int8_t type, const u_char* packet)
{
    /* Handle arp argument depending on type */
    #if (type == NARP_REPLY)
        #define arp_current arp_rep_l
    #else
        #define arp_current arp_req_l
    #endif


    struct arp_current *new_arp;
    new_arp = (struct arp_current *)arp;

    /* Populate basic common arp info */
    new_arp->count = 1;
    new_arp->next = NULL;

    /* Allocate memory for ip addrs */
    new_arp->sip = (char *) malloc (sizeof(char) * 16);
    new_arp->dip = (char *) malloc (sizeof(char) * 16);

    /* Source IP */
    sprintf(new_arp->sip, "%d.%d.%d.%d",
            packet[28], packet[29], packet[30], packet[31]);

    /* Destination IP */
    sprintf(new_arp->dip, "%d.%d.%d.%d",
            packet[38], packet[39], packet[40], packet[41]);
}

/* Init device for libnet and get mac addr */
void lnet_init(char *disp)
{
	
   char error[LIBNET_ERRBUF_SIZE];
	libnet = NULL;
	
	/* Init libnet */
	libnet = libnet_init(LIBNET_LINK, disp, error);
	if (libnet == NULL) {
		printf("libnet_init() falied: %s", error);
		exit(EXIT_FAILURE);
	}
	
	/* Get our mac addr */
	if (ourmac == NULL) {
		struct libnet_ether_addr *mymac;
		mymac = libnet_get_hwaddr(libnet);
		memcpy(smac, mymac, ETH_ALEN);
		
		ourmac = (char *) malloc (sizeof(char) * 18);
		sprintf(ourmac, "%02x:%02x:%02x:%02x:%02x:%02x",
			smac[0], smac[1], smac[2], 
			smac[3], smac[4], smac[5]);
	}

}


/* Forge Arp Packet, using libnet */
void forge_arp(char *source_ip, char *dest_ip, char *disp)
{
	static libnet_ptag_t arp=0, eth=0;
	//static u_char dmac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	static u_char dmac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	static u_char sip[IP_ALEN];
	static u_char dip[IP_ALEN];
	u_int32_t otherip, myip;
	
	/* get src & dst ip address */
   otherip = libnet_name2addr4(libnet, dest_ip, LIBNET_RESOLVE);
   memcpy(dip, (char*)&otherip, IP_ALEN);
	
	myip = libnet_name2addr4(libnet, source_ip, LIBNET_RESOLVE);
   memcpy(sip, (char*)&myip, IP_ALEN);
	
	/* forge arp data */
	arp = libnet_build_arp(
      ARPHRD_ETHER,
      ETHERTYPE_IP,
      ETH_ALEN, IP_ALEN,
      ARPOP_REQUEST,
      smac, sip,
      dmac, dip,
      NULL, 0,
      libnet,
      arp);
 
	/* forge ethernet header */
   eth = libnet_build_ethernet(
      dmac, smac,
      ETHERTYPE_ARP,
      NULL, 0,
      libnet,
      eth);
	
	/* Inject the packet */
   libnet_write(libnet);
}


void lnet_destroy()
{
	libnet_destroy(libnet);
}
