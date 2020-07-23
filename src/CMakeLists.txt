cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 14)

project(X11_Clippy)

set(CMAKE_BUILD_TYPE Debug)


add_executable(client tcpclient.c)
add_executable(server tcpserver.cpp proxyutils.cpp)

target_link_libraries(client -luv)
target_link_libraries(server -luv)