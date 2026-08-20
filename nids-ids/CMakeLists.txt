cmake_minimum_required(VERSION 3.15)
project(nids LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

add_executable(nids
  src/main.cpp
  src/pcap_reader.cpp
  src/decode.cpp
  src/ac.cpp
  src/rules.cpp
  src/engine.cpp
)
target_include_directories(nids PRIVATE include)
