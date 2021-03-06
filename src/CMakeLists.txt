cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 14)

project(tdmux)

set(CMAKE_BUILD_TYPE Debug)

if ( CMAKE_COMPILER_IS_GNUCC )
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -ggdb3")
endif()
if ( MSVC )
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /W4")
endif()

add_executable(client tcpClient.c)
add_executable(server tcpServer.cpp proxyUtils.cpp requestProcessor.cpp configManager.cpp sslProcessor.cpp)

include_directories(server ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(client -luv)
target_link_libraries(server -luv -lssl -lcrypto)