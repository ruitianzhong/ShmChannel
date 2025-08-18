cmake_minimum_required(VERSION 3.10)

project(ShmChannel C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Werror -g)

find_library(PCAP_LIB pcap)
if( ${PCAP_LIB} STREQUAL "PCAP_LIB-NOTFOUND" )
message(FATAL_ERROR "Please install pcap library")
endif()

set(SHM_CHANNEL_SOURCES
    ./src/shm_channel.c
    ./src/shm_channel.h   
)
enable_testing()
set(MAIN_SOURCES
    ./src/main.c
    ${SHM_CHANNEL_SOURCES}
)

# include_directories(include)

# add_executable(myapp ${SOURCES})

include_directories(./src)
add_library(shm_channel ${SHM_CHANNEL_SOURCES})

# add_executable(smoke_test ${MAIN_SOURCES})


add_executable(test_burst_request ./src/test/test_burst_request.c
                        ${SHM_CHANNEL_SOURCES})

add_executable(test_single_request ./src/test/test_single_request.c
                ${SHM_CHANNEL_SOURCES})

add_executable(send_recv ./src/send_recv.c ${SHM_CHANNEL_SOURCES})

target_link_libraries(send_recv PRIVATE ${PCAP_LIB})
