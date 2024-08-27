cmake_minimum_required(VERSION 3.16)
project(sigil_capture C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -Wextra -pedantic")

include_directories(include)

set(SIGIL_SOURCES
    src/sigil_ring.c
    src/sigil_shm.c
    src/sigil_pcap_fast.c
    src/sigil_capture.c
)

add_library(sigil_capture_static STATIC ${SIGIL_SOURCES})
find_package(Threads REQUIRED)
target_link_libraries(sigil_capture_static Threads::Threads)

add_executable(sigil-capture src/main.c)
target_link_libraries(sigil-capture sigil_capture_static Threads::Threads)

# Test executables
enable_testing()

add_executable(test_ring tests/test_ring.c)
target_link_libraries(test_ring sigil_capture_static Threads::Threads)
add_test(NAME test_ring COMMAND test_ring)

add_executable(test_pcap_fast tests/test_pcap_fast.c)
target_link_libraries(test_pcap_fast sigil_capture_static Threads::Threads)
add_test(NAME test_pcap_fast COMMAND test_pcap_fast)
