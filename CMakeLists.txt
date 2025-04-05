cmake_minimum_required(VERSION 3.26)
project(code C)

set(CMAKE_C_STANDARD 11)

add_executable(rsa cw2/rsa.c)
add_executable(dh cw2/diffie-hellman.c)
add_executable(eg cw2/el-gamal.c)
