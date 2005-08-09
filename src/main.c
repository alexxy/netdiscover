/***************************************************************************
 *            main.c
 *
 *  Sun Jul  3 07:35:24 2005
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
 
#define _GNU_SOURCE
#define VERSION "0.3-beta3"

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "ifaces.h"
#include "screen.h"


/* Threads data structure */
struct t_data {
	char *disp;
	char *sip;
	int autos;
};


void start_sniffer_thread(struct t_data *datos);
void start_arp_thread(struct t_data *datos);
void *SnifferThread(void *arg);
void *InjectArp(void *arg);
void *screen_refresh(void *arg);
void scan_range(char *disp, char *sip);
void usage();

/* Common local networks to scan */
/* Add new networks if needed here */
char *common_net[] = {
	"172.16.0.0/16",
	"192.168.0.0/16",
	"172.26.0.0/16",
	"172.27.0.0/16",
	"172.17.0.0/16",
	"172.18.0.0/16",
	"172.19.0.0/16",
	"172.20.0.0/16",
	"172.21.0.0/16",
	"172.22.0.0/16",
	"172.23.0.0/16",
	"172.24.0.0/16",
	"172.25.0.0/16",
	"172.28.0.0/16",
	"172.29.0.0/16",
	"172.30.0.0/16",
	"172.31.0.0/16",
	"10.0.0.0/8",
	NULL
};


pthread_t injection, sniffer, screen;
int sleept, fastmode, node;


/* main, what is this? */
int main(int argc, char **argv)
{
	int c;
	int esniff = 0;
	int earp = 0;
	int erange = 0;
	struct t_data datos;
	
	datos.sip = NULL;
	datos.autos = 0;
	sleept = 0;
	node = 67;
	
	current_network = (char *) malloc ((sizeof(char)) * 16);
	sprintf(current_network,"Starting.");
	
	/* Fetch parameters */
	while ((c = getopt(argc, argv, "i:m:s:r:n:hf")) != EOF)
	{
		switch (c)
		{
			case 'i':
				datos.disp = (char *) malloc (sizeof(char) * strlen(optarg));
				sprintf(datos.disp, "%s", optarg);
				lnetInit(optarg);
				break;
			
			case  'm':

				if (strcmp(optarg, "passive") == 0)
				{
					esniff = 1;
				}
				else if (strcmp(optarg, "scan") == 0)
				{
					earp = 1;
				}
				else if (strcmp(optarg, "auto") == 0)
				{
					earp = 1;
					datos.autos = 1;
				}
				else
				{
					printf("Unknown mode\n");
					exit(1);
				}
				break;
			
			case  's':
				sleept = (int)atoi(optarg);
				break;
			
			case  'n':
				node = (int)atoi(optarg);
				break;
			
			case  'r':
				datos.sip = (char *) malloc (sizeof(char) * strlen(optarg));
				sprintf(datos.sip, "%s", optarg);
				erange = 1;
				break;
			
			case  'f':
				fastmode = 1;
				break;
			
			case 'h':
				usage(argv[0]);
				exit(1);
				break;
			
			default:
				break;
		}
	}

	
	init_lists();
	system("clear");
	
	if ( ((earp == 1) && (erange == 1)) || ((earp == 1) && (datos.autos == 1)) )
	{
		if (pthread_create(&screen, NULL, screen_refresh, (void *)NULL))
			perror("Could not create thread");
		
		start_sniffer_thread(&datos);
		start_arp_thread(&datos);
		pthread_join(sniffer,NULL);
		pthread_join(injection,NULL);
	}
	else if (esniff ==  1)
	{
		if (pthread_create(&screen, NULL, screen_refresh, (void *)NULL))
			perror("Could not create thread");
		
		current_network = "(passive)";
		start_sniffer_thread(&datos);
		pthread_join(sniffer,NULL);
	}
	else
	{
		usage(argv[0]);
		exit(1);
	}


	return 0;
}


void start_arp_thread(struct t_data *datos)
{
	
	if (pthread_create(&injection, NULL, InjectArp, (void *)datos))
		perror("Could not create thread");
	
}


void start_sniffer_thread(struct t_data *datos)
{
	
	if (pthread_create(&sniffer, NULL, SnifferThread, (void *)datos))
		perror("Could not create thread");
	
	
}


void *screen_refresh(void *arg)
{
	
	while (1==1)
	{
		print_screen();
		sleep(1);
	}
	
}


void *SnifferThread(void *arg)
{
	struct t_data *datos = (struct t_data *)arg;
	StartSniffer(datos->disp);
	return NULL;
}


/* Inject ARP Replys to the network */
void *InjectArp(void *arg)
{
	sleep(2);
	
	struct t_data *datos = (struct t_data *)arg;
	
	if ( datos->autos != 1 )
	{
		scan_range(datos->disp, datos->sip);
	}
	else
	{
		int x = 0;
		
		while (common_net[x] != NULL)
		{
			scan_range(datos->disp, common_net[x]);
			x += 1;
		}
		
	}
	
	sprintf(current_network,"Finished!");
	lnetDestroy();
	
	return NULL;
}


/* Scan range, using arp requests */
void scan_range(char *disp, char *sip)
{
	int i, j, k, e;
	const char delimiters[] = ".,/";
	char *a, *b, *c, *d;
	char *test, *fromip, *tnet;

	test = (char *) malloc ((sizeof(char)) * 16);
	fromip = (char *) malloc ((sizeof(char)) * 16);
	tnet = (char *) malloc ((sizeof(char)) * 19);
	
	sprintf(tnet, "%s", sip);
	a = strtok (tnet, delimiters); /* 1st ip octect */
	b = strtok (NULL, delimiters); /* 2nd ip octect */
	c = strtok (NULL, delimiters); /* 3rd ip octect */
	d = strtok (NULL, delimiters); /* 4th ip octect */
	e = atoi(strtok (NULL, delimiters)); /* Subnet mask */

	
	/* Scan class C network */
	if ( e == 24)
	{
		sprintf(fromip,"%s.%s.%s.%i", a, b, c, node);
		sprintf(current_network,"%s.%s.%s.0/%i", a, b, c, e);
		//setip(disp, test, "255.255.255.0");
		
		for (j=1; j<255; j++)
		{
			sprintf(test,"%s.%s.%s.%i", a, b, c, j);
			ForgeArp(fromip, test, disp);	
		}
	}
	/* Scan class B network */
	else if ( e == 16)
	{
	
		for (i=0; i<256; i++)
		{
			sprintf(fromip,"%s.%s.%i.%i", a, b, i, node);
			sprintf(current_network,"%s.%s.%i.0/%i", a, b, i, e);
			
			/* Check if fastmode is enabled */
			if (fastmode != 1)
			{
				for (j=1; j<255; j++)
				{
					sprintf(test,"%s.%s.%i.%i", a, b, i, j);
					ForgeArp(fromip, test, disp);	
				}
			}
			else
			{
				sprintf(test,"%s.%s.%i.1", a, b, i);
				ForgeArp(fromip, test, disp);	
				
				sprintf(test,"%s.%s.%i.100", a, b, i);
				ForgeArp(fromip, test, disp);	
				
				sprintf(test,"%s.%s.%i.254", a, b, i);
				ForgeArp(fromip, test, disp);	
			}
			
			if (sleept != 0)
			{
				usleep(sleept * 1000);
			}
			else
			{
				usleep(1 * 1000);
			}
		}
	
	}
	/* Scan class A network */
	else if ( e == 8)
	{
		for (k=0; k<256; k++)
		{
			for (i=0; i<256; i++)
			{
				sprintf(fromip,"%s.%i.%i.%i", a, k, i, node);
				sprintf(current_network,"%s.%i.%i.0/%i", a, k, i, e);
				
				/* Check if fastmode is enabled */
				if (fastmode != 1)
				{
					for (j=1; j<255; j++)
					{
						sprintf(test,"%s.%i.%i.%i", a, k, i, j);
						ForgeArp(fromip, test, disp);	
					}
				}
				else
				{
					sprintf(test,"%s.%i.%i.1", a, k, i);
					ForgeArp(fromip, test, disp);	
					
					sprintf(test,"%s.%i.%i.100", a, k, i);
					ForgeArp(fromip, test, disp);	
					
					sprintf(test,"%s.%i.%i.254", a, k, i);
					ForgeArp(fromip, test, disp);	
				}
				
				if (sleept != 0)
				{
					usleep(sleept * 1000);
				}
				else
				{
					usleep(1 * 1000);
				}
			}
		}
	}
	else
	{
		system("clear");
		printf("Network range must be 0.0.0.0/8 , /16 or /24\n");
		exit(1);
	}
	
	free(test);
}


void usage(char *comando)
{
	printf("Netdiscover %s [Active/passive reconnaissance tool]\n", VERSION);
	printf("Written by: Jaime Penalba <jpenalbae@gmail.com>\n\n");
	printf("Usage: %s -i device -m mode [-r range] [-s time] [-n node] [-f]\n", comando);
	printf("  -i device: your network device\n");
	printf("  -m modes\n");
	printf("    auto: scan common networks (try it with -f)\n");
	printf("    scan: scan given /8, /16 or /24 network range\n");
	printf("    passive: do not send anything, only sniff\n");
	printf("  -r range: 192.168.6.0/24, 192.168.0.0/16 or 10.0.0.0/8\n");
	printf("  -s time: time to sleep between network change (miliseconds)\n");
	printf("  -n node: last ip octet used for scanning (from 2 to 253)\n");
	printf("  -f enable fastmode scan, saves a lot of time, recommended for auto\n");
}
