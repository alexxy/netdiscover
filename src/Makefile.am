## Process this file with automake to produce Makefile.in

## Created by Anjuta - will be overwritten
## If you don't want it to overwrite it,
## 	Please disable it in the Anjuta project configuration

INCLUDES =

AM_CFLAGS =\
	 -DDEBUG_LEVEL_2\
	 -Wall\
	 -g

sbin_PROGRAMS = netdiscover

netdiscover_SOURCES = \
	main.c\
	ifaces.c\
	screen.c\
	ifaces.h\
	screen.h\
	fhandle.c\
	fhandle.h\
	misc.c\
	misc.h\
	oui.h

netdiscover_LDFLAGS = 

netdiscover_LDADD = \
	 -lpthread -lpcap -lnet

