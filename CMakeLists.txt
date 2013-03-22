cmake_minimum_required(VERSION 2.8)
project(NetDiscover)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Threads)
find_package(PCAP)
find_package(LibNET)

set(SBIN_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/sbin")
set(MAN_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share/man")

add_subdirectory(src)
add_subdirectory(man)
