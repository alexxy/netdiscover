/***************************************************************************
 *            main.c
 *
 *  Sun Jul  3 07:35:24 2005
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
 
#define _GNU_SOURCE
#define VERSION "0.3-beta7"

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include "ifaces.h"
#include "screen.h"
#include "fhandle.h"

#define RPATH  "%s/.netdiscover/ranges"
#define FPATH  "%s/.netdiscover/fastips"


void *inject_arp(void *arg);
void *screen_refresh(void *arg);
void *parsable_screen_refresh(void *arg);
void scan_range(char *disp, char *sip);
void usage();


/* Last octect of ips scaned in fast mode */
/* Add new addr if needed here */
char **fast_ips;
char *dfast_ips[] = { "1", "2", "100", "200", "254", NULL};

/* Common local networks to scan */
/* Add new networks if needed here */
char **common_net;
char *dcommon_net[] = {
   "192.168.0.0/16",
   "172.16.0.0/16",
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


pthread_t injection, sniffer, screen, keys;
int fastmode, pcount, node, ssleep, ignoreconf;
long sleept;


/* Read control keys */
void *keys_thread(void *arg)
{
    while ( 1 == 1 )
    {
        read_key();
    }
}


/* main, fetch params and start */
int main(int argc, char **argv)
{
   int c;
   int esniff = 0;
   int erange = 0;
   int elist = 0;
   char *plist;

   /* Config file handling vars */
   char *home, *path;

   struct t_data datos;

   /* Some default values */
   datos.sip = NULL;
   datos.disp = NULL;
   datos.filter = NULL;
   datos.autos = 0;
   sleept = 99;
   node = 67;
   pcount = 1;

   /* Globals defined in screen.h */
   parsable_output = 0;
   continue_listening = 0;

   current_network = (char *) malloc ((sizeof(char)) * 16);
   sprintf(current_network, "Starting.");

   /* Fetch parameters */
   while ((c = getopt(argc, argv, "i:s:r:l:n:c:F:pSfdPLh")) != EOF)
   {
      switch (c)
      {
         case 'i':   /* Set the interface */
            datos.disp = (char *) malloc (sizeof(char) * (strlen(optarg) + 1));
            sprintf(datos.disp, "%s", optarg);
            break;

         case 'p':   /* Enable passive mode */
            esniff = 1;
            break;

         case  's':  /* Set sleep time */
            sleept = atol(optarg);
            break;

         case  'S':  /* Enable sleep supression */
            ssleep = 1;
            break;

         case  'c':  /* Set no. of times to repeat the scan */
            pcount = atoi(optarg);
            break;

         case  'n':  /* Set las used octect */
            node = atoi(optarg);
            break;

         case  'r':  /* Set the range to scan */
            datos.sip = (char *) malloc (sizeof(char) * strlen(optarg) + 1);
            sprintf(datos.sip, "%s", optarg);
            erange = 1;
            break;

         case 'l':   /* Scan ranges on the given file */
            plist = (char *) malloc (sizeof(char) * (strlen(optarg) + 1));
            sprintf(plist, "%s", optarg);
            elist = 1;
            break;

         case  'f':  /* Enable fast mode */
            fastmode = 1;
            break;

         case 'F':  /* Edit pcap filter */
            datos.filter = (char *) malloc (sizeof(char) * (strlen(optarg) + 1));
            sprintf(datos.filter, "%s", optarg);
            break;

         case 'd':   /* Ignore home config files */
            ignoreconf = 1;
            break;

         case 'P':   /* Produces parsable output (vs interactive screen) */
            parsable_output = 1;
            break;

         case 'L':   /* Continue to listen in parsable output mode after active scan is completed */
            parsable_output = 1;
            continue_listening = 1;
            break;

	 default:
	    printf("\n"); /* continues... */

         case 'h':   /* Show help */
            usage(argv[0]);
            exit(1);
            break;
      }
   }

   if (optind < argc) {
      printf("Invalid extra argument: %s\n\n", argv[optind]);
      usage(argv[0]);
      exit(1);
   }


   /* Check for uid 0 */
   if ( getuid() && geteuid() )
   {
      printf("You must be root to run this.\n");
      exit(1);
   }

   /* If no iface was specified, autoselect one. exit, if no one available */
   if (datos.disp == NULL)
   {
      datos.disp = pcap_lookupdev(errbuf);

      if (datos.disp == NULL)
      {
         printf("Couldn't find default device: %s\n", errbuf);
         exit(1);
      }
   }

   /* Load user config files or set defaults */
   home = getenv("HOME");

   /* Read user configured ranges if arent disabled */
   path = (char *) malloc (sizeof(char) * (strlen(home) + strlen(RPATH) + 1));
   sprintf(path, RPATH, home);

   if (((common_net = fread_list(path)) == NULL) || (ignoreconf == 1))
      common_net = dcommon_net;
   free(path);

   /* Read user configured ips for fast mode if arent disabled */
   path = (char *) malloc (sizeof(char) * (strlen(home) + strlen(FPATH) + 1));
   sprintf(path, FPATH, home);

   if(((fast_ips = fread_list(path)) == NULL) || (ignoreconf == 1))
      fast_ips = dfast_ips;
   free(path);

   /* Read range list given by user if specified */
   if (elist == 1) {
      if ((common_net = fread_list(plist)) == NULL) {
         printf("File \"%s\" containing ranges, cannot be read.\n", plist);
         exit(1);
      }
   }

   /* Init libnet and lists */
   lnet_init(datos.disp);
   init_lists();

   /* If no mode was selected, enable auto scan */
   if ((erange != 1) && (esniff != 1))
      datos.autos = 1;

   /* Start the execution */
   if (parsable_output) {
      pthread_create(&screen, NULL, parsable_screen_refresh, (void *)NULL);

   } else {
      system("clear");
      pthread_create(&screen, NULL, screen_refresh, (void *)NULL);
      pthread_create(&keys, NULL, keys_thread, (void *)NULL);
   }

   pthread_create(&sniffer, NULL, start_sniffer, (void *)&datos);

   if (esniff == 1) {
      current_network = "(passive)";
      pthread_join(sniffer,NULL);

   } else {
      if (pthread_create(&injection, NULL, inject_arp, (void *)&datos))
         perror("Could not create injection thread");

      pthread_join(sniffer,NULL);
   }

   if(datos.filter != NULL)
	   free(datos.filter);

   return 0;
}


/* Refresh screen function called by screen thread */
void *screen_refresh(void *arg)
{
    while (1==1)
    {
        print_screen();
        sleep(1);
    }
}

/* Refresh parsable screen function called by screen thread */
void *parsable_screen_refresh(void *arg)
{
	print_header();
	while (1==1)
	{
		print_parsable_screen();
        usleep(500000); /* half a second */
	}
}

/* Start the arp injection on the given network device */
void *inject_arp(void *arg)
{
   struct t_data *datos;

   datos = (struct t_data *)arg;
   sleep(2);

   /* Scan the given range, or start the auto scan mode */
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
         x++;
      }

      free(common_net);
   }

   /* Wait for last arp replys and mark as scan finished */
   sleep(2);
   sprintf(current_network, "Finished!");
   lnet_destroy();

   if(parsable_output)
   {
      parsable_output_scan_completed(); /* defined in screen.c */
   }

   return NULL;
}


/* Scan 255 hosts network */
void scan_net(char *disp, char *sip)
{
   int x, j;
   char test[16], fromip[16];

   sprintf(fromip,"%s.%i", sip, node);

   /* Repeat given times */
   for (x=0;x<pcount;x++)
   {

      /* Check if fastmode is enabled */
      if (fastmode != 1)
      {
         for (j=1; j<255; j++)
         {
            sprintf(test,"%s.%i", sip, j);
            forge_arp(fromip, test, disp);

            /* Check sleep time supression */
            if (ssleep != 1)
            {
               /* Sleep time */
               if (sleept != 99)
                  usleep(sleept * 1000);
               else
                  usleep(1 * 1000);
            }
         }
      }
      else
      {
         j = 0;

         while (fast_ips[j] != NULL)
         {
            sprintf(test,"%s.%s", sip, fast_ips[j]);
            forge_arp(fromip, test, disp);
            j++;

            /* Check sleep time supression */
            if (ssleep != 1)
            {
               /* Sleep time */
               if (sleept != 99)
                  usleep(sleept * 1000);
               else
                  usleep(1 * 1000);
            }
         }
      }

      /* If sleep supression is enabled, sleep each 255 hosts */
      if (ssleep == 1)
      {
         /* Sleep time */
         if (sleept != 99)
            usleep(sleept * 1000);
         else
            usleep(1 * 1000);
      }

   }
}


/* Scan range, using arp requests */
void scan_range(char *disp, char *sip)
{
   int i, k, e;
   const char delimiters[] = ".,/";
   char *a, *b, *c, *d, *aux;
   char tnet[19], net[16];

   /* Split range data*/
   snprintf(tnet, sizeof(tnet), "%s", sip);
   a = strtok (tnet, delimiters); /* 1st ip octect */
   b = strtok (NULL, delimiters); /* 2nd ip octect */
   c = strtok (NULL, delimiters); /* 3rd ip octect */
   d = strtok (NULL, delimiters); /* 4th ip octect */

   if ((aux = strtok (NULL, delimiters)) != NULL) /* Subnet mask */
      e = atoi(aux); /* Subnet mask */
   else
      e = 24; /* Default subnet mask */

   /* Check all parts are ok */
   if ((a == NULL) || (b == NULL) || (c == NULL) || (d == NULL))
   {
   	e = -1;
   } else {
        k = strtol(a, &aux, 10);
        if (k<0 || k>255 || *aux != '\0') e = -1;
        k = strtol(b, &aux, 10);
        if (k<0 || k>255 || *aux != '\0') e = -1;
        k = strtol(c, &aux, 10);
        if (k<0 || k>255 || *aux != '\0') e = -1;
        k = strtol(d, &aux, 10);
        if (k<0 || k>255 || *aux != '\0') e = -1;
   }

   /* Scan class C network */
   if ( e == 24)
   {
      sprintf(net, "%s.%s.%s", a, b, c);
      sprintf(current_network,"%s.0/%i", net, e);
      scan_net(disp, net);

   }/* Scan class B network */
   else if ( e == 16)
   {
      for (i=0; i<256; i++)
      {
         sprintf(net, "%s.%s.%i", a, b, i);
         sprintf(current_network,"%s.%s.%i.0/%i", a, b, i, e);
         scan_net(disp, net);
      }

   } /* Scan class A network */
   else if ( e == 8)
   {
      for (k=0; k<256; k++)
      {
         for (i=0; i<256; i++)
         {
            sprintf(net, "%s.%i.%i", a, k, i);
            sprintf(current_network,"%s.%i.%i.0/%i", a, k, i, e);
            scan_net(disp, net);
         }
      }
   }
   else
   {
      // system("clear");
      printf("\nERROR: Network range must be 0.0.0.0/8 , /16 or /24\n\n");
      sighandler(SIGTERM);
      sleep(5);
      exit(1);
   }

}


/* Print usage instructions */
void usage(char *comando)
{
   printf("Netdiscover %s [Active/passive arp reconnaissance tool]\n"
      "Written by: Jaime Penalba <jpenalbae@gmail.com>\n\n"
      "Usage: %s [-i device] [-r range | -l file | -p] [-s time] [-n node] "
      "[-c count] [-f] [-d] [-S] [-P] [-C]\n"
      "  -i device: your network device\n"
      "  -r range: scan a given range instead of auto scan. 192.168.6.0/24,/16,/8\n"
      "  -l file: scan the list of ranges contained into the given file\n"
      "  -p passive mode: do not send anything, only sniff\n"
      "  -F filter: Customize pcap filter expression (default: \"arp\")\n"
      "  -s time: time to sleep between each arp request (miliseconds)\n"
      "  -n node: last ip octet used for scanning (from 2 to 253)\n"
      "  -c count: number of times to send each arp reques (for nets with packet loss)\n"
      "  -f enable fastmode scan, saves a lot of time, recommended for auto\n"
      "  -d ignore home config files for autoscan and fast mode\n"
      "  -S enable sleep time supression betwen each request (hardcore mode)\n"
      "  -P print results in a format suitable for parsing by another program\n"
      "  -L in parsable output mode (-P), continue listening after the active scan is completed\n\n"
      "If -r, -l or -p are not enabled, netdiscover will scan for common lan addresses.\n",
      VERSION, comando);
}
