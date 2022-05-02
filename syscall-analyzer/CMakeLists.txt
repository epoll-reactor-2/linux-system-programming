cmake_minimum_required(VERSION 3.22)
project(syscall_analyzer C)

set(CMAKE_C_STANDARD 17)

add_library(syscall_analyzer_lib SHARED syscall-analyzer.c)

add_executable(syscall_analyzer util.c)
target_link_libraries(syscall_analyzer syscall_analyzer_lib)
