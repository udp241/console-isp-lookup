cmake_minimum_required(VERSION 3.10)
project(isp C)

if(NOT WIN32)
  message(FATAL_ERROR "isp uses WinHTTP and only builds on Windows")
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(isp lookup.c isp.rc)
target_link_libraries(isp PRIVATE winhttp ws2_32)

if(MINGW)
  target_link_options(isp PRIVATE -static)
endif()
