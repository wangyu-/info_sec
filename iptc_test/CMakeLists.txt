cmake_minimum_required(VERSION 3.13)
project(iptc_test C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(nat.out
        libiptc/libip4tc.c
        nat.c)
