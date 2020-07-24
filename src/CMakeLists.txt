cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 14)

project(X11_Clippy)

set(CMAKE_BUILD_TYPE Debug)

if ( CMAKE_COMPILER_IS_GNUCC )
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")
endif()
if ( MSVC )
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /W4")
endif()

add_executable(client tcpclient.c)
add_executable(server tcpserver.cpp proxyutils.cpp)

include_directories(server ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(client -luv)
target_link_libraries(server -luv)