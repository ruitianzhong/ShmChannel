cmake_minimum_required(VERSION 3.16)
project(iterconv CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# 产物统一输出到仓库根 bin/, 与 vm.py 的启动路径一致
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# json.hpp 与 common/protocol.h 可从仓库根或 common/ 按名引
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/common)

find_package(Threads REQUIRED)

add_executable(agent agent/agent.cpp)
target_compile_options(agent PRIVATE -Wall -Wextra)
target_link_libraries(agent PRIVATE Threads::Threads)

add_executable(controller controller/controller.cpp controller/ctl.cpp)
target_compile_options(controller PRIVATE -Wall -Wextra)
target_link_libraries(controller PRIVATE Threads::Threads)