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


#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
	
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <time.h>
#include <libnet.h>
#include "screen.h"
#include "ifaces.h"

/* tcpdump header (ether.h) defines ETHER_HDRLEN)  */
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


/* Shitty globals */
libnet_t *libnet;
static u_char smac[ETH_ALEN];
struct p_header *temp_header;


/* Start Sniffing on given iface */
void StartSniffer(char *disp)
{
	pcap_t *descr;
	descr = pcap_open_live(disp, BUFSIZ, 1, PCAP_TOUT, errbuf);
	
	if(descr == NULL) 
	{
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}
	
	pcap_loop(descr, -1, (pcap_handler)ProccessPacket, NULL);

}


/* Handle Headers and IP data */
/* from the recived pcap_loop packet */
void ProccessPacket(u_char *args, struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	
	u_int16_t type = handle_ethernet(args,pkthdr,packet);
	
	if(type == ETHERTYPE_IP)
	{	
		//printf("Type: IP\n\n");
		//handle_IP(args,pkthdr,packet);
		
	} else if(type == ETHERTYPE_ARP)
	{
		//printf("Type: ARP\n\n");
		handle_ARP(pkthdr,packet);
		
		print_screen();

		
	} else if(type == ETHERTYPE_REVARP)
	{
		printf("Type: RARP\n\n");
		print_screen();
		
 	} else
	{
		//printf("Type: Unknown\n\n");
	}
	
}



/* Handle Ethernet Header from Packet */
u_int16_t handle_ethernet
        (u_char *args, struct pcap_pkthdr *pkthdr, const u_char *packet)
{

	struct ether_header *eptr;
	struct p_header *new_header;
	u_int caplen = pkthdr->caplen;
	u_int length = pkthdr->len;
	u_short ether_type;
	u_char *temporal;
	char *from;

	if (caplen < ETHER_HDRLEN)
	{
		fprintf(stdout,"Packet length less than ethernet header length\n");
		return -1;
	}

	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;
	ether_type = ntohs(eptr->ether_type);
	
	from = (char *) malloc (sizeof(char) * 18);
	
	#if defined(sun) && (defined(__svr4__) || defined(__SVR4))
		temporal = &eptr->ether_shost.ether_addr_octet;
	#else
		temporal = eptr->ether_shost;
	#endif
	
	sprintf(from, "%02x:%02x:%02x:%02x:%02x:%02x", 
		temporal[0], temporal[1],
		temporal[2], temporal[3],
		temporal[4], temporal[5]);
	
	if(ether_type != ETHERTYPE_ARP)
	{
		return ether_type;
		
	}
	
	/* Ignore if is from us */
	if (strcmp(ourmac, from ) == 0)
	{
		return 0x069;
	}
	
	new_header = (struct p_header *) malloc (sizeof(struct p_header));
	new_header->smac = (char *) malloc (sizeof(char) * strlen(from));
	new_header->dmac = (char *) malloc (sizeof(char) * 18);
	new_header->length = (unsigned int)length;
	
	#if defined(sun) && (defined(__svr4__) || defined(__SVR4))
		temporal = &eptr->ether_dhost.ether_addr_octet;
	#else
		temporal = eptr->ether_dhost;
	#endif
	
	sprintf(new_header->smac, "%s", from);
	sprintf(new_header->dmac, "%02x:%02x:%02x:%02x:%02x:%02x",
		temporal[0], temporal[1],
		temporal[2], temporal[3],
		temporal[4], temporal[5]);
	
	temp_header = new_header;
	
	return ether_type;
}


/* Prints Info about the arp packet */
void handle_ARP(struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct arphdr *harp;
	struct ether_arp *earp;
	//u_char ipsrc[17];
	//u_char ipdst[17];


	harp = (struct arphdr *) (packet + ETH_HLEN);
	earp = (struct ether_arp *) (packet + ETH_HLEN);


	if ( ntohs(harp->ar_op) == ARPOP_REQUEST )
	{
		//printf("\tARP: Request\n");
		//char *type = "Request";
	}
	else if ( ntohs(harp->ar_op) == ARPOP_REPLY )
	{
		struct arp_rep_l *new_arprep_l;
		new_arprep_l = (struct arp_rep_l *) malloc (sizeof(struct arp_rep_l));
		new_arprep_l->sip = (char *) malloc (sizeof(char) * 16);
		new_arprep_l->dip = (char *) malloc (sizeof(char) * 16);


		new_arprep_l->header = temp_header;
		
		sprintf(new_arprep_l->sip, "%d.%d.%d.%d",
			earp->arp_spa[0], earp->arp_spa[1],
			earp->arp_spa[2], earp->arp_spa[3]);

		sprintf(new_arprep_l->dip, "%d.%d.%d.%d",
			earp->arp_tpa[0], earp->arp_tpa[1],
			earp->arp_tpa[2], earp->arp_tpa[3]);
		
		new_arprep_l->count = 1;
		new_arprep_l->next = NULL;
		
		arprep_add(new_arprep_l);
	}
	
}

void lnetInit(char *disp)
{
	
   char error[LIBNET_ERRBUF_SIZE];
	libnet = NULL;
		
	libnet = libnet_init(LIBNET_LINK, disp, error);
	
	if (libnet == NULL)
	{
		printf("libnet_init() falied: %s", error);
		exit(EXIT_FAILURE);
	}
	
	if (ourmac == NULL)
	{
		// get hwaddr
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
void ForgeArp(char *source_ip, char *dest_ip, char *disp)
{
	static libnet_ptag_t arp=0, eth=0;
	
	//static u_char dmac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	static u_char dmac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	static u_char sip[IP_ALEN];
	static u_char dip[IP_ALEN];
	
	// get src & dst ip address
   u_int32_t otherip, myip;
   otherip = libnet_name2addr4(libnet, dest_ip, LIBNET_RESOLVE);
   memcpy(dip, (char*)&otherip, IP_ALEN);
	
	myip = libnet_name2addr4(libnet, source_ip, LIBNET_RESOLVE);
   memcpy(sip, (char*)&myip, IP_ALEN);
	
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
 
   eth = libnet_build_ethernet(
      dmac, smac,
      ETHERTYPE_ARP,
      NULL, 0,
      libnet,
      eth);
		
   libnet_write(libnet);
}


void lnetDestroy()
{
	libnet_destroy(libnet);
}
