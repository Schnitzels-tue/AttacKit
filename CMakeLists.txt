cmake_minimum_required(VERSION 3.12)

# Set the project name and version
project(AttacKit VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(PCAP_ROOT ${CMAKE_SOURCE_DIR}/thirdparty/npcap-sdk)
if(WIN32)
    include_directories(${CMAKE_SOURCE_DIR}/thirdparty/boost-sdk)
else()
    find_package(Boost REQUIRED COMPONENTS system)
endif()

# Check if we are in Debug mode and define the DEBUG macro
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_definitions(-DDEBUG)  # Define DEBUG for Debug builds
endif()

include(CTest)
enable_testing()

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(core)
add_subdirectory(cli)
add_subdirectory(logging)
