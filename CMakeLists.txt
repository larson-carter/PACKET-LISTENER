cmake_minimum_required(VERSION 3.28)
project(PACKET_LISTENER C)

set(CMAKE_C_STANDARD 23)

add_executable(PACKET_LISTENER main.c)

find_library(PCAP_LIBRARY pcap)
if (PCAP_LIBRARY)
    target_link_libraries(PACKET_LISTENER ${PCAP_LIBRARY})
else()
    message(FATAL_ERROR "libpcap not found")
endif()