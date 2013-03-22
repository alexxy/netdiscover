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
