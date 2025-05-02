cmake_minimum_required(VERSION 3.12)

# Set the project name and version
project(AttacKit VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)
enable_testing()

# Disable treating VLA warnings as errors for any compiler
# Temporary
add_compile_options(-Wvla -Wno-error=vla)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src/core)
add_subdirectory(src/cli)
