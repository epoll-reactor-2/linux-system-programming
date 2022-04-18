cmake_minimum_required(VERSION 3.22)
project(syscall_analyzer C)

set(CMAKE_C_STANDARD 17)

add_library(syscall_analyzer SHARED syscall_analyzer.c)

add_executable(syscall_analyzer_tests tests.c syscall_analyzer)