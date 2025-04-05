cmake_minimum_required(VERSION 3.26)
project(code C)

set(CMAKE_C_STANDARD 11)

add_executable(rsa rsa.c)
add_executable(dh diffie-hellman.c)
add_executable(eg el-gamal.c)
