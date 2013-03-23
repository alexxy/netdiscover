#
#  netdiscover - An active/passive address reconnaissance tool
#
#  Copyright (C) 2013 Alexey Shvetsov <alexxy@gentoo.org
#
#  This file is part of netdiscover.
#
#  netdiscover is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  netdiscover is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with netdiscover.  If not, see <http://www.gnu.org/licenses/>.
#

add_executable(netdiscover
		main.c
		ifaces.c
		screen.c
		fhandle.c
		misc.c
		data_reply.c
		data_request.c
		data_unique.c
		)
target_link_libraries(netdiscover ${CMAKE_THREAD_LIBS_INIT} ${PCAP_LIBRARIES}
	${LIBNET_LIBRARIES})

install(TARGETS netdiscover DESTINATION sbin)
