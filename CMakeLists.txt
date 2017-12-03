cmake_minimum_required(VERSION 3.9)
project(opensslSvr)

set(CMAKE_CXX_STANDARD 11)

#include_directories(/home/dongbo/boringssl-chromium-stable/include)
#link_directories(/home/dongbo/boringssl-chromium-stable/ssl /home/dongbo/boringssl-chromium-stable/crypto/)

add_executable(opensslSvr main.cpp)
target_link_libraries(opensslSvr ssl crypto pthread)