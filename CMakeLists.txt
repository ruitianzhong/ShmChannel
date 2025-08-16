# 指定CMake最低版本要求
cmake_minimum_required(VERSION 3.10)

project(ShmChannel C)

# 设置C标准版本（例如C11）
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 添加编译选项（可选，如开启警告）
add_compile_options(-Wall -Wextra -Werror)


set(SOURCES
    ./src/shm_channel.c
    ./src/shm_channel.h   
)

# include_directories(include)

# add_executable(myapp ${SOURCES})

add_library(shm_channel ${SOURCES})

# target_link_libraries(myapp m)
