# 指定CMake最低版本要求
cmake_minimum_required(VERSION 3.10)

project(ShmChannel C)

# 设置C标准版本（例如C11）
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 添加编译选项（可选，如开启警告）
add_compile_options(-Wall -Wextra -Werror -g)


set(SHM_CHANNEL_SOURCES
    ./src/shm_channel.c
    ./src/shm_channel.h   
)

set(MAIN_SOURCES
    ./src/main.c
    ${SHM_CHANNEL_SOURCES}
)

message(${MAIN_SOURCES})

# include_directories(include)

# add_executable(myapp ${SOURCES})

include_directories(./src)
add_library(shm_channel ${SHM_CHANNEL_SOURCES})

add_executable(smoke_test ${MAIN_SOURCES})

# target_link_libraries(myapp m)
