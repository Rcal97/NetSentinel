cmake_minimum_required(VERSION 3.20)
project(NetSentinel VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(include)

set(SOURCES
    src/main.cpp
    src/PacketCapture.cpp
    src/PacketAnalyzer.cpp
    src/RuleEngine.cpp
    src/AlertManager.cpp
)

add_executable(NetSentinel ${SOURCES})

target_link_libraries(NetSentinel ${PCAP_LIBRARIES})
target_include_directories(NetSentinel PRIVATE ${PCAP_INCLUDE_DIRS})
target_compile_options(NetSentinel PRIVATE ${PCAP_CFLAGS_OTHER})