cmake_minimum_required(VERSION 3.12)

# Set the project name and version
project(poisoners_kit VERSION 1.0)

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

# Add the include directory
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Add source files
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
    src/*.cpp
)

# Create the executable
add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})

# -- Dependencies --
add_subdirectory(thirdparty/PcapPlusPlus)
# Link the PcapPlusPlus libraries to your executable
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
    Common++
    Packet++
    Pcap++
)
